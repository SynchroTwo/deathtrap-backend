package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.OtpLog;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.LoginRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.common.types.enums.UserStatus;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

/** Handles creator login and session creation. */
@RestController
@RequestMapping("/auth")
public class LoginHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginHandler.class);
    private static final long SESSION_DAYS = 7L;
    private static final int MAX_ATTEMPTS = 3;
    private static final int LOCK_MINUTES = 30;

    private static final String SELECT_USER_BY_MOBILE =
            "SELECT user_id, full_name, date_of_birth, mobile, email, address, pan_ref, aadhaar_ref, " +
            "kyc_status, status, risk_accepted_at, zero_nominee_risk_version, locker_completeness_pct, " +
            "last_reviewed_at, inactivity_trigger_months, created_at, updated_at, deleted_at " +
            "FROM users WHERE mobile = ? AND deleted_at IS NULL LIMIT 1";
    private static final String SELECT_OTP =
            "SELECT otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, locked_until, expires_at, created_at " +
            "FROM otp_log WHERE party_id = ? AND channel = ?::otp_channel_enum AND purpose = 'login'::otp_purpose_enum AND verified = false " +
            "ORDER BY created_at DESC LIMIT 1";
    private static final String UPDATE_ATTEMPTS =
            "UPDATE otp_log SET attempts = attempts + 1 WHERE otp_id = ?";
    private static final String UPDATE_LOCKED =
            "UPDATE otp_log SET attempts = attempts + 1, locked_until = ? WHERE otp_id = ?";
    private static final String UPDATE_VERIFIED =
            "UPDATE otp_log SET verified = true WHERE otp_id = ?";
    private static final String INSERT_SESSION =
            "INSERT INTO sessions (session_id, party_id, party_type, jwt_jti, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?, ?, ?)";

    private static final RowMapper<User> USER_MAPPER = (rs, row) -> new User(
            rs.getString("user_id"), rs.getString("full_name"),
            rs.getDate("date_of_birth").toLocalDate(),
            rs.getString("mobile"), rs.getString("email"),
            rs.getString("address"), rs.getString("pan_ref"), rs.getString("aadhaar_ref"),
            KycStatus.valueOf(rs.getString("kyc_status").toUpperCase()),
            UserStatus.valueOf(rs.getString("status").toUpperCase()),
            rs.getTimestamp("risk_accepted_at") != null ? rs.getTimestamp("risk_accepted_at").toInstant() : null,
            rs.getObject("zero_nominee_risk_version", Integer.class),
            rs.getInt("locker_completeness_pct"),
            rs.getTimestamp("last_reviewed_at") != null ? rs.getTimestamp("last_reviewed_at").toInstant() : null,
            rs.getInt("inactivity_trigger_months"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant(),
            rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toInstant() : null);

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
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs LoginHandler with required dependencies. */
    public LoginHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/session — verifies both OTPs inline and issues a JWT session. */
    @PostMapping("/session")
    public ResponseEntity<ApiResponse<Map<String, Object>>> login(
            @RequestBody @Valid LoginRequest request) {

        User user = dbClient.queryOne(SELECT_USER_BY_MOBILE, USER_MAPPER, request.mobile())
                .orElseThrow(() -> AppException.notFound("user"));

        if (user.status() != UserStatus.ACTIVE) {
            throw AppException.forbidden();
        }

        Instant now = Instant.now();
        String partyId = user.mobile();

        OtpLog mobileOtpLog = fetchOtp(partyId, "sms", now);
        verifyAndMark(mobileOtpLog, request.mobileOtp(), now);

        OtpLog emailOtpLog = fetchOtp(partyId, "email", now);
        verifyAndMark(emailOtpLog, request.emailOtp(), now);

        String sessionId = CsprngUtil.randomUlid();
        Instant expiresAt = now.plus(SESSION_DAYS, ChronoUnit.DAYS);
        String jwt = jwtService.issueToken(user.userId(), PartyType.CREATOR, sessionId);

        dbClient.execute(INSERT_SESSION, sessionId, user.userId(), sessionId, expiresAt, now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.SESSION_CREATED, AuditResult.SUCCESS)
                .actorId(user.userId()).actorType(PartyType.CREATOR).sessionId(sessionId).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of(
                "accessToken", jwt,
                "sessionId", sessionId,
                "expiresAt", expiresAt.toString());
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    private OtpLog fetchOtp(String partyId, String channel, Instant now) {
        OtpLog otpLog = dbClient.queryOne(SELECT_OTP, OTP_MAPPER, partyId, channel)
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
                throw AppException.otpLocked(lockUntil);
            }
            dbClient.execute(UPDATE_ATTEMPTS, otpLog.otpId());
            throw AppException.otpInvalid();
        }

        dbClient.execute(UPDATE_VERIFIED, otpLog.otpId());
    }
}
