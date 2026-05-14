package in.deathtrap.auth.routes.otp;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.OtpLog;
import in.deathtrap.common.types.dto.VerifyEmailOtpRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles email OTP verification. Only REGISTRATION purpose is supported.
 *  Issues verifiedToken once both email and the linked mobile have been verified;
 *  otherwise returns "awaiting mobile verification". */
@RestController
@RequestMapping("/auth/otp")
public class VerifyEmailOtpHandler {

    private static final Logger log = LoggerFactory.getLogger(VerifyEmailOtpHandler.class);
    private static final int MAX_ATTEMPTS = 3;
    private static final int LOCK_MINUTES = 30;

    private static final String SELECT_OTP =
            "SELECT otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, locked_until, expires_at, created_at " +
            "FROM otp_log WHERE party_id = ? AND channel = ?::otp_channel_enum AND purpose = ?::otp_purpose_enum AND verified = false " +
            "ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_VERIFIED_OTP =
            "SELECT otp_id FROM otp_log WHERE party_id = ? AND channel = ?::otp_channel_enum " +
            "AND purpose = ?::otp_purpose_enum AND verified = true ORDER BY created_at DESC LIMIT 1";
    private static final String UPDATE_ATTEMPTS =
            "UPDATE otp_log SET attempts = attempts + 1 WHERE otp_id = ?";
    private static final String UPDATE_LOCKED =
            "UPDATE otp_log SET attempts = attempts + 1, locked_until = ? WHERE otp_id = ?";
    private static final String UPDATE_VERIFIED =
            "UPDATE otp_log SET verified = true WHERE otp_id = ?";

    private static final RowMapper<OtpLog> OTP_MAPPER = (rs, row) -> new OtpLog(
            rs.getString("otp_id"),
            rs.getString("party_id"),
            PartyType.valueOf(rs.getString("party_type").toUpperCase()),
            OtpChannel.valueOf(rs.getString("channel").toUpperCase()),
            OtpPurpose.valueOf(rs.getString("purpose").toUpperCase()),
            rs.getString("otp_hash"),
            rs.getInt("attempts"),
            rs.getBoolean("verified"),
            rs.getTimestamp("locked_until") != null ? rs.getTimestamp("locked_until").toInstant() : null,
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("created_at").toInstant());

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    public VerifyEmailOtpHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyEmail(
            @RequestBody @Valid VerifyEmailOtpRequest request) {

        if (request.purpose() != OtpPurpose.REGISTRATION) {
            throw AppException.validationFailed(
                    Map.of("purpose", "Email OTP verification is only supported for REGISTRATION"));
        }

        Instant now = Instant.now();
        String purpose = request.purpose().name().toLowerCase();

        OtpLog otpRow = fetchOtp(request.email(), "email", purpose, now);
        verifyAndMark(otpRow, request.otp(), now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_VERIFIED, AuditResult.SUCCESS)
                .actorId(request.email()).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();

        boolean mobileVerified = dbClient.queryOne(SELECT_VERIFIED_OTP, STRING_MAPPER,
                request.mobile(), "sms", purpose).isPresent();
        if (!mobileVerified) {
            return ResponseEntity.ok(ApiResponse.ok(
                    Map.of("message", "Email verified. Verify mobile to complete registration.",
                            "mobileVerified", false, "emailVerified", true),
                    requestId));
        }

        // PartyId for the issued token is the mobile (matches the registration primary key
        // used downstream by /auth/register).
        String verifiedToken = jwtService.issueVerifiedToken(request.mobile(), request.purpose());
        return ResponseEntity.ok(ApiResponse.ok(
                Map.of("verifiedToken", verifiedToken, "expiresInSeconds", 900),
                requestId));
    }

    private OtpLog fetchOtp(String partyId, String channel, String purpose, Instant now) {
        OtpLog otpLog = dbClient.queryOne(SELECT_OTP, OTP_MAPPER, partyId, channel, purpose)
                .orElseThrow(() -> AppException.notFound("otp"));
        if (otpLog.expiresAt().isBefore(now)) {
            throw AppException.otpExpired();
        }
        if (otpLog.lockedUntil() != null && otpLog.lockedUntil().isAfter(now)) {
            throw AppException.otpLocked(otpLog.lockedUntil());
        }
        return otpLog;
    }

    private void verifyAndMark(OtpLog otpLog, String submittedOtp, Instant now) {
        boolean matches = MessageDigest.isEqual(
                Sha256Util.hashHex(submittedOtp).getBytes(StandardCharsets.UTF_8),
                otpLog.otpHash().getBytes(StandardCharsets.UTF_8));

        if (!matches) {
            int newAttempts = otpLog.attempts() + 1;
            if (newAttempts >= MAX_ATTEMPTS) {
                Instant lockUntil = now.plusSeconds(LOCK_MINUTES * 60L);
                dbClient.execute(UPDATE_LOCKED, lockUntil, otpLog.otpId());
                auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_FAILED, AuditResult.BLOCKED)
                        .actorId(otpLog.partyId()).actorType(PartyType.CREATOR).build());
                throw AppException.otpLocked(lockUntil);
            }
            dbClient.execute(UPDATE_ATTEMPTS, otpLog.otpId());
            auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_FAILED, AuditResult.FAILURE)
                    .actorId(otpLog.partyId()).actorType(PartyType.CREATOR).build());
            throw AppException.otpInvalid();
        }

        dbClient.execute(UPDATE_VERIFIED, otpLog.otpId());
    }
}
