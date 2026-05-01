package in.deathtrap.auth.routes.creator;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.auth.config.JwtService;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles session logout and token revocation. */
@RestController
@RequestMapping("/auth")
public class LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(LogoutHandler.class);

    private static final String UPDATE_SESSION_REVOKED =
            "UPDATE sessions SET revoked_at = NOW() WHERE session_id = ?";
    private static final String INSERT_REVOKED_TOKEN =
            "INSERT INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, NOW(), ?) ON CONFLICT (jti) DO NOTHING";

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs LogoutHandler with required dependencies. */
    public LogoutHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** DELETE /auth/session — revokes the current session and blacklists the JWT. */
    @DeleteMapping("/session")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        String token = authHeader.substring(7);
        JwtPayload payload = jwtService.validateToken(token);

        Instant tokenExpiry = Instant.ofEpochSecond(payload.exp());
        dbClient.execute(UPDATE_SESSION_REVOKED, payload.jti());
        dbClient.execute(INSERT_REVOKED_TOKEN, payload.jti(), tokenExpiry);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.SESSION_REVOKED, AuditResult.SUCCESS)
                .actorId(payload.sub()).actorType(payload.partyType()).sessionId(payload.jti()).build());

        return ResponseEntity.noContent().build();
    }
}
