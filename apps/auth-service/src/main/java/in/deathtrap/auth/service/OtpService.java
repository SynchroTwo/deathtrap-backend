package in.deathtrap.auth.service;

import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

/** Handles OTP generation, hashing (SHA-256), storage, verification, and rate limiting. */
@Service
public class OtpService {

    private static final Logger log = LoggerFactory.getLogger(OtpService.class);
    private static final int OTP_MODULUS = 1_000_000;
    private static final int EXPIRY_SECONDS = 600;
    private static final int MAX_ATTEMPTS = 3;
    private static final int LOCK_MINUTES = 30;
    private static final int RATE_LIMIT_PER_HOUR = 3;

    private static final String SELECT_EXISTING_OTP =
            "SELECT expires_at FROM otp_log " +
            "WHERE party_id = ? AND channel = ?::otp_channel_enum AND purpose = ?::otp_purpose_enum " +
            "AND verified = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1";

    private static final String COUNT_HOURLY_OTPS =
            "SELECT COUNT(*) FROM otp_log " +
            "WHERE party_id = ? AND purpose = ?::otp_purpose_enum " +
            "AND created_at > NOW() - INTERVAL '1 hour'";

    private static final String SELECT_LOCKED =
            "SELECT locked_until FROM otp_log " +
            "WHERE party_id = ? AND locked_until > NOW() ORDER BY locked_until DESC LIMIT 1";

    private static final String INSERT_OTP =
            "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, " +
            "attempts, verified, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?::otp_channel_enum, ?::otp_purpose_enum, ?, 0, false, ?, ?)";

    private static final String SELECT_OTP_FOR_VERIFY =
            "SELECT otp_id, otp_hash, attempts, locked_until, expires_at FROM otp_log " +
            "WHERE party_id = ? AND channel = ?::otp_channel_enum AND purpose = ?::otp_purpose_enum " +
            "AND verified = false ORDER BY created_at DESC LIMIT 1";

    private static final String UPDATE_ATTEMPTS =
            "UPDATE otp_log SET attempts = attempts + 1 WHERE otp_id = ?";

    private static final String UPDATE_LOCKED =
            "UPDATE otp_log SET attempts = attempts + 1, locked_until = ? WHERE otp_id = ?";

    private static final String UPDATE_VERIFIED =
            "UPDATE otp_log SET verified = true WHERE otp_id = ?";

    private record OtpRecord(String otpId, String otpHash, int attempts,
                              Instant lockedUntil, Instant expiresAt) {}

    private static final RowMapper<OtpRecord> OTP_RECORD_MAPPER = (rs, row) -> new OtpRecord(
            rs.getString("otp_id"),
            rs.getString("otp_hash"),
            rs.getInt("attempts"),
            rs.getTimestamp("locked_until") != null ? rs.getTimestamp("locked_until").toInstant() : null,
            rs.getTimestamp("expires_at").toInstant());

    private final DbClient dbClient;

    /** Constructs OtpService with required dependencies. */
    public OtpService(DbClient dbClient) {
        this.dbClient = dbClient;
    }

    /**
     * Checks if an unexpired OTP already exists for this party+channel+purpose.
     * Returns expiry instant if one exists, empty otherwise.
     */
    public java.util.Optional<Instant> getActiveOtpExpiry(String partyId, OtpChannel channel, OtpPurpose purpose) {
        return dbClient.queryOne(SELECT_EXISTING_OTP,
                (rs, row) -> rs.getTimestamp(1).toInstant(),
                partyId, channel.name().toLowerCase(), purpose.name().toLowerCase());
    }

    /**
     * Checks rate limit (max 3 OTPs per party per hour per purpose).
     * Throws AppException.rateLimited() if exceeded.
     */
    public void checkRateLimit(String partyId, OtpPurpose purpose) {
        Integer count = dbClient.queryOne(COUNT_HOURLY_OTPS,
                (rs, row) -> rs.getInt(1),
                partyId, purpose.name().toLowerCase()).orElse(0);
        if (count >= RATE_LIMIT_PER_HOUR) {
            log.warn("OTP rate limit exceeded for partyId={} purpose={}", partyId, purpose);
            throw AppException.rateLimited();
        }
    }

    /**
     * Generates a 6-digit OTP, SHA-256 hashes it, stores it in otp_log, and returns the plaintext OTP.
     */
    public String generateAndStore(String partyId, OtpChannel channel, OtpPurpose purpose) {
        byte[] randBytes = CsprngUtil.randomBytes(4);
        int value = ((randBytes[0] & 0xFF) << 24 | (randBytes[1] & 0xFF) << 16
                | (randBytes[2] & 0xFF) << 8 | (randBytes[3] & 0xFF)) & Integer.MAX_VALUE;
        String otp = String.format("%06d", value % OTP_MODULUS);
        String otpHash = sha256Hex(otp);

        String otpId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(EXPIRY_SECONDS);

        dbClient.execute(INSERT_OTP,
                otpId, partyId, channel.name().toLowerCase(),
                purpose.name().toLowerCase(), otpHash, expiresAt, now);

        return otp;
    }

    /**
     * Verifies a submitted OTP using constant-time SHA-256 comparison.
     * Throws AppException on any failure (expired, locked, invalid).
     * Marks as verified on success.
     */
    public void verify(String partyId, String submittedOtp, OtpChannel channel, OtpPurpose purpose) {
        OtpRecord record = dbClient.queryOne(SELECT_OTP_FOR_VERIFY, OTP_RECORD_MAPPER,
                partyId, channel.name().toLowerCase(), purpose.name().toLowerCase())
                .orElseThrow(() -> AppException.notFound("otp"));

        Instant now = Instant.now();

        if (record.expiresAt().isBefore(now)) {
            throw AppException.otpExpired();
        }
        if (record.lockedUntil() != null && record.lockedUntil().isAfter(now)) {
            throw AppException.otpLocked(record.lockedUntil());
        }

        String submittedHash = sha256Hex(submittedOtp);
        boolean matches = MessageDigest.isEqual(
                submittedHash.getBytes(StandardCharsets.UTF_8),
                record.otpHash().getBytes(StandardCharsets.UTF_8));

        if (!matches) {
            int newAttempts = record.attempts() + 1;
            if (newAttempts >= MAX_ATTEMPTS) {
                Instant lockUntil = now.plusSeconds(LOCK_MINUTES * 60L);
                dbClient.execute(UPDATE_LOCKED, lockUntil, record.otpId());
                log.warn("OTP locked for partyId={} channel={} purpose={}", partyId, channel, purpose);
                throw AppException.otpLocked(lockUntil);
            }
            dbClient.execute(UPDATE_ATTEMPTS, record.otpId());
            throw AppException.otpInvalid();
        }

        dbClient.execute(UPDATE_VERIFIED, record.otpId());
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }
}
