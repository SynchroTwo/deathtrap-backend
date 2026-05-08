package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.config.JwtService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles POST /trigger/halt — allows a creator to cancel a fraudulent recovery within the 48h window. */
@RestController
@RequestMapping("/trigger/halt")
public class HaltHandler {

    private static final Logger log = LoggerFactory.getLogger(HaltHandler.class);

    private static final String SELECT_INITIATED_SESSION =
            "SELECT session_id, creator_id, trigger_id FROM recovery_sessions " +
            "WHERE creator_id = ? AND status = 'initiated' ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_VALID_OTP =
            "SELECT otp_id FROM otp_log WHERE party_id = ? AND purpose = 'mfa' AND verified = TRUE " +
            "AND created_at > NOW() - INTERVAL '15 minutes' LIMIT 1";
    private static final String CANCEL_SESSION =
            "UPDATE recovery_sessions SET status = 'cancelled', updated_at = NOW() WHERE session_id = ?";
    private static final String HALT_TRIGGER =
            "UPDATE trigger_events SET status = 'halted', updated_at = NOW() WHERE trigger_id = ?";

    private static final RowMapper<SessionRow> SESSION_MAPPER = (rs, row) -> new SessionRow(
            rs.getString("session_id"), rs.getString("creator_id"), rs.getString("trigger_id"));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs HaltHandler with required dependencies. */
    public HaltHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /trigger/halt — requires MFA OTP, cancels initiated session, halts trigger event. */
    @PostMapping
    public ResponseEntity<ApiResponse<Map<String, String>>> halt(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        String creatorId = jwt.sub();

        List<SessionRow> sessions = dbClient.query(SELECT_INITIATED_SESSION, SESSION_MAPPER, creatorId);
        if (sessions.isEmpty()) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "No haltable recovery session found. Session may have already progressed or expired.");
        }
        SessionRow session = sessions.get(0);

        List<String> otpRows = dbClient.query(SELECT_VALID_OTP,
                (rs, row) -> rs.getString(1), creatorId);
        if (otpRows.isEmpty()) {
            throw new AppException(ErrorCode.AUTH_SESSION_INVALID,
                    "MFA OTP verification required to halt recovery.");
        }

        dbClient.withTransaction(status -> {
            dbClient.execute(CANCEL_SESSION, session.sessionId());
            dbClient.execute(HALT_TRIGGER, session.triggerId());
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.TRIGGER_HALTED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR)
                .targetId(session.triggerId())
                .metadataJson(Map.of("sessionId", session.sessionId(), "reason", "creator_halt"))
                .build());

        log.info("Recovery halted: creatorId={} sessionId={} triggerId={}",
                creatorId, session.sessionId(), session.triggerId());

        return ResponseEntity.ok(ApiResponse.ok(
                Map.of("message", "Recovery halted successfully. You are marked as alive."),
                UUID.randomUUID().toString()));
    }

    record SessionRow(String sessionId, String creatorId, String triggerId) {}
}
