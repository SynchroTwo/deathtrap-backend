package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.RefreshSessionRequest;
import in.deathtrap.common.types.dto.RefreshSessionResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles refresh-token exchange for a fresh session JWT.
 *  No Authorization header — the refresh token in the body authenticates the call.
 *  The supplied refresh token and the new refresh token share the same JTI
 *  (= session_id), so this endpoint does NOT rotate the underlying session;
 *  the old refresh token remains valid until its natural expiry. */
@RestController
@RequestMapping("/auth/session")
public class RefreshSessionHandler {

    private static final Logger log = LoggerFactory.getLogger(RefreshSessionHandler.class);

    private static final String SELECT_SESSION =
            "SELECT session_id, revoked_at, expires_at FROM sessions WHERE session_id = ? LIMIT 1";
    private static final String SELECT_REVOKED =
            "SELECT jti FROM revoked_tokens WHERE jti = ? LIMIT 1";

    private static final RowMapper<SessionRow> SESSION_MAPPER = (rs, row) -> new SessionRow(
            rs.getString("session_id"),
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null,
            rs.getTimestamp("expires_at").toInstant());
    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs RefreshSessionHandler with required dependencies. */
    public RefreshSessionHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/session/refresh — exchanges a valid refresh token for fresh tokens. */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshSessionResponse>> refresh(
            @RequestBody @Valid RefreshSessionRequest request) {

        JwtPayload payload = jwtService.validateRefreshToken(request.refreshToken());
        String sessionId = payload.jti();

        SessionRow session = dbClient.queryOne(SELECT_SESSION, SESSION_MAPPER, sessionId)
                .orElseThrow(() -> AppException.notFound("session"));

        if (session.revokedAt() != null) {
            throw AppException.sessionRevoked();
        }
        if (dbClient.queryOne(SELECT_REVOKED, STRING_MAPPER, sessionId).isPresent()) {
            throw AppException.sessionRevoked();
        }
        Instant now = Instant.now();
        if (session.expiresAt().isBefore(now)) {
            throw AppException.sessionExpired();
        }

        String newSessionJwt = jwtService.issueToken(payload.sub(), payload.partyType(), sessionId);
        String newRefreshToken = jwtService.issueRefreshToken(payload.sub(), payload.partyType(), sessionId);
        Instant accessTokenExpiresAt = now.plusSeconds(jwtService.getAccessTokenSeconds());

        auditWriter.write(AuditWritePayload.builder(AuditEventType.SESSION_CREATED, AuditResult.SUCCESS)
                .actorId(payload.sub()).actorType(payload.partyType()).sessionId(sessionId)
                .build());

        String requestId = UUID.randomUUID().toString();
        RefreshSessionResponse body = new RefreshSessionResponse(
                newSessionJwt, newRefreshToken, accessTokenExpiresAt.toString());
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    record SessionRow(String sessionId, Instant revokedAt, Instant expiresAt) {}
}
