package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.OtpLog;
import in.deathtrap.common.types.dto.VerifyOtpRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles OTP verification requests. */
@RestController
@RequestMapping("/auth/otp")
public class VerifyOtpHandler {

    private static final Logger log = LoggerFactory.getLogger(VerifyOtpHandler.class);
    private static final BCryptPasswordEncoder BCRYPT = new BCryptPasswordEncoder();
    private static final int MAX_ATTEMPTS = 3;
    private static final int LOCK_MINUTES = 30;

    private static final String SELECT_OTP =
            "SELECT otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, locked_until, expires_at, created_at " +
            "FROM otp_log WHERE party_id = ? AND purpose = ?::otp_purpose_enum AND verified = false " +
            "ORDER BY created_at DESC LIMIT 1";
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

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    /** Constructs VerifyOtpHandler with required dependencies. */
    public VerifyOtpHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/otp/verify — verifies a submitted OTP against the stored hash. */
    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyOtp(
            @RequestBody @Valid VerifyOtpRequest request) {

        OtpLog otpLog = dbClient.queryOne(SELECT_OTP, OTP_MAPPER,
                request.partyId(), request.purpose().name().toLowerCase())
                .orElseThrow(() -> AppException.notFound("otp"));

        Instant now = Instant.now();

        if (otpLog.expiresAt().isBefore(now)) {
            throw AppException.otpExpired();
        }
        if (otpLog.lockedUntil() != null && otpLog.lockedUntil().isAfter(now)) {
            throw AppException.otpLocked(otpLog.lockedUntil());
        }

        boolean matches = BCRYPT.matches(request.otp(), otpLog.otpHash());

        if (!matches) {
            int newAttempts = otpLog.attempts() + 1;
            if (newAttempts >= MAX_ATTEMPTS) {
                Instant lockUntil = now.plusSeconds(LOCK_MINUTES * 60L);
                dbClient.execute(UPDATE_LOCKED, lockUntil, otpLog.otpId());
                auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_FAILED, AuditResult.BLOCKED)
                        .actorId(request.partyId()).actorType(PartyType.CREATOR).build());
                throw AppException.otpLocked(lockUntil);
            }
            dbClient.execute(UPDATE_ATTEMPTS, otpLog.otpId());
            auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_FAILED, AuditResult.FAILURE)
                    .actorId(request.partyId()).actorType(PartyType.CREATOR).build());
            throw AppException.otpInvalid();
        }

        dbClient.execute(UPDATE_VERIFIED, otpLog.otpId());
        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_VERIFIED, AuditResult.SUCCESS)
                .actorId(request.partyId()).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of(
                "verified", true,
                "partyId", request.partyId(),
                "verificationToken", otpLog.otpId());
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }
}
