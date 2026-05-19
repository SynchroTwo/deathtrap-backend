package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.LoginRequest;
import in.deathtrap.common.types.dto.LoginResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.common.types.enums.UserStatus;
import jakarta.validation.Valid;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles creator login and session creation.
 *  Expects the mobile OTP to have been verified beforehand via
 *  /auth/otp/verify-mobile with purpose=login; the resulting verifiedToken
 *  is carried in the Authorization: Bearer header here. */
@RestController
@RequestMapping("/auth")
public class LoginHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginHandler.class);
    private static final long SESSION_DAYS = 7L;

    private static final String SELECT_USER_BY_MOBILE =
            "SELECT user_id, full_name, date_of_birth, mobile, email, address, pan_ref, " +
            "kyc_status, status, risk_accepted_at, zero_nominee_risk_version, locker_completeness_pct, " +
            "last_reviewed_at, inactivity_trigger_months, created_at, updated_at, deleted_at " +
            "FROM users WHERE mobile = ? AND deleted_at IS NULL LIMIT 1";
    private static final String SELECT_VERIFIED_LOGIN_OTP =
            "SELECT otp_id FROM otp_log WHERE party_id = ? AND channel = 'sms'::otp_channel_enum " +
            "AND purpose = 'login'::otp_purpose_enum AND verified = true " +
            "ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_SALT =
            "SELECT salt_hex FROM party_salts " +
            "WHERE party_id = ? AND party_type = 'creator'::party_type_enum LIMIT 1";
    private static final String SELECT_ACTIVE_PRIVKEY =
            "SELECT ciphertext_b64, nonce_b64, auth_tag_b64 FROM encrypted_privkey_blobs " +
            "WHERE party_id = ? AND party_type = 'creator'::party_type_enum AND is_active = TRUE LIMIT 1";
    private static final String INSERT_SESSION =
            "INSERT INTO sessions (session_id, party_id, party_type, jwt_jti, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?, ?, ?)";

    private static final RowMapper<User> USER_MAPPER = (rs, row) -> new User(
            rs.getString("user_id"), rs.getString("full_name"),
            rs.getDate("date_of_birth").toLocalDate(),
            rs.getString("mobile"), rs.getString("email"),
            rs.getString("address"), rs.getString("pan_ref"),
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

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<PrivkeyBlob> PRIVKEY_MAPPER = (rs, row) ->
            new PrivkeyBlob(rs.getString("ciphertext_b64"), rs.getString("nonce_b64"), rs.getString("auth_tag_b64"));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs LoginHandler with required dependencies. */
    public LoginHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/session — issues session + refresh JWTs and returns the
     *  client's encrypted-privkey material so the UI can derive its in-memory
     *  keys via runLoginCryptoPipeline. */
    @PostMapping("/session")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @RequestBody @Valid LoginRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        jwtService.validateVerifiedToken(authHeader.substring(7));

        // Cross-check: a verified sms+login otp_log row must exist for this mobile.
        // Defends against re-using a verifiedToken from a different mobile.
        dbClient.queryOne(SELECT_VERIFIED_LOGIN_OTP, STRING_MAPPER, request.mobile())
                .orElseThrow(() -> AppException.unauthorized());

        User user = dbClient.queryOne(SELECT_USER_BY_MOBILE, USER_MAPPER, request.mobile())
                .orElseThrow(() -> AppException.notFound("user"));

        if (user.status() != UserStatus.ACTIVE) {
            throw AppException.forbidden();
        }

        String saltHex = dbClient.queryOne(SELECT_SALT, STRING_MAPPER, user.userId())
                .orElseThrow(() -> AppException.notFound("party_salt"));
        PrivkeyBlob privkey = dbClient.queryOne(SELECT_ACTIVE_PRIVKEY, PRIVKEY_MAPPER, user.userId())
                .orElseThrow(() -> AppException.notFound("encrypted_privkey_blob"));

        Instant now = Instant.now();
        String sessionId = CsprngUtil.randomUlid();
        Instant sessionExpiresAt = now.plus(SESSION_DAYS, ChronoUnit.DAYS);
        Instant accessTokenExpiresAt = now.plusSeconds(jwtService.getAccessTokenSeconds());

        String sessionJwt = jwtService.issueToken(user.userId(), PartyType.CREATOR, sessionId);
        String refreshToken = jwtService.issueRefreshToken(user.userId(), PartyType.CREATOR, sessionId);

        dbClient.execute(INSERT_SESSION, sessionId, user.userId(), sessionId, sessionExpiresAt, now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.SESSION_CREATED, AuditResult.SUCCESS)
                .actorId(user.userId()).actorType(PartyType.CREATOR).sessionId(sessionId).build());

        String requestId = UUID.randomUUID().toString();
        LoginResponse body = new LoginResponse(
                user.userId(),
                PartyType.CREATOR.name().toLowerCase(),
                sessionJwt,
                refreshToken,
                accessTokenExpiresAt.toString(),
                saltHex,
                privkey.ciphertextB64(),
                privkey.nonceB64(),
                privkey.authTagB64());
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    record PrivkeyBlob(String ciphertextB64, String nonceB64, String authTagB64) {}
}
