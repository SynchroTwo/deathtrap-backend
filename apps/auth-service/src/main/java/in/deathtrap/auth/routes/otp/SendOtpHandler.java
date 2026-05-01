package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.SendOtpRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles OTP issuance requests. */
@RestController
@RequestMapping("/auth/otp")
public class SendOtpHandler {

    private static final Logger log = LoggerFactory.getLogger(SendOtpHandler.class);
    private static final Pattern E164_INDIA = Pattern.compile("^\\+91[6-9]\\d{9}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final int OTP_EXPIRY_SECONDS = 600;
    private static final int OTP_DIGITS = 1_000_000;

    private static final String SELECT_LOCKED_OTP =
            "SELECT locked_until FROM otp_log WHERE party_id = ? AND locked_until > NOW() LIMIT 1";
    private static final String INSERT_OTP =
            "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?::otp_channel_enum, ?::otp_purpose_enum, ?, 0, false, ?, ?)";

    private static final RowMapper<Instant> INSTANT_MAPPER = (rs, row) -> rs.getTimestamp(1).toInstant();

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    /** Constructs SendOtpHandler with required dependencies. */
    public SendOtpHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/otp/send — generates and stores a 6-digit SHA-256-hashed OTP per channel. */
    @PostMapping("/send")
    public ResponseEntity<ApiResponse<Map<String, Object>>> sendOtp(
            @RequestBody @Valid SendOtpRequest request) {

        validateContact(request);

        String partyId = request.mobile() != null ? request.mobile() : request.email();
        String purpose = request.purpose().name().toLowerCase();
        Instant now = Instant.now();

        Optional<Instant> lockedUntil = dbClient.queryOne(SELECT_LOCKED_OTP, INSTANT_MAPPER, partyId);
        if (lockedUntil.isPresent()) {
            throw AppException.otpLocked(lockedUntil.get());
        }

        if (request.mobile() != null) {
            insertOtp(partyId, "sms", purpose, now);
        }
        if (request.email() != null) {
            insertOtp(partyId, "email", purpose, now);
        }

        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_ISSUED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of("message", "OTP sent", "expiresIn", OTP_EXPIRY_SECONDS);
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    private void insertOtp(String partyId, String channel, String purpose, Instant now) {
        byte[] randBytes = CsprngUtil.randomBytes(4);
        int value = ((randBytes[0] & 0xFF) << 24 | (randBytes[1] & 0xFF) << 16
                | (randBytes[2] & 0xFF) << 8 | (randBytes[3] & 0xFF)) & Integer.MAX_VALUE;
        String otp = String.format("%06d", value % OTP_DIGITS);
        String otpHash = Sha256Util.hashHex(otp);
        String otpId = CsprngUtil.randomUlid();
        Instant expiresAt = now.plusSeconds(OTP_EXPIRY_SECONDS);
        dbClient.execute(INSERT_OTP, otpId, partyId, channel, purpose, otpHash, expiresAt, now);
        log.info("[DEV-OTP] {} OTP for party={}: {}", channel.toUpperCase(), partyId, otp);
    }

    private void validateContact(SendOtpRequest request) {
        if (request.mobile() == null && request.email() == null) {
            throw AppException.validationFailed(Map.of("contact", "Either mobile or email is required"));
        }
        if (request.mobile() != null && !E164_INDIA.matcher(request.mobile()).matches()) {
            throw AppException.validationFailed(Map.of("mobile", "Must be E.164 format: +91XXXXXXXXXX"));
        }
        if (request.email() != null && !EMAIL_PATTERN.matcher(request.email()).matches()) {
            throw AppException.validationFailed(Map.of("email", "Invalid email format"));
        }
    }
}
