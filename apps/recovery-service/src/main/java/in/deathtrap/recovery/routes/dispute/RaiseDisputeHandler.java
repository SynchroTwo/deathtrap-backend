package in.deathtrap.recovery.routes.dispute;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.RaiseDisputeRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles raising a dispute to pause an active recovery session. */
@RestController
@RequestMapping("/recovery/dispute")
public class RaiseDisputeHandler {

    private static final Logger log = LoggerFactory.getLogger(RaiseDisputeHandler.class);

    private static final String SELECT_SESSION =
            "SELECT session_id, creator_id, trigger_id, blob_id, status, initiated_at, " +
            "locked_until, completed_at, created_at FROM recovery_sessions WHERE session_id = ? LIMIT 1";
    private static final String SELECT_AUTH_LAYER =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND party_id = ? LIMIT 1";
    private static final String INSERT_DISPUTE =
            "INSERT INTO dispute_log (dispute_id, session_id, raised_by, raised_by_type, " +
            "reason, status, raised_at, created_at) VALUES (?, ?, ?, ?, ?, 'open', NOW(), NOW())";
    private static final String UPDATE_SESSION_DISPUTED =
            "UPDATE recovery_sessions SET status = 'disputed', updated_at = NOW() WHERE session_id = ?";

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs RaiseDisputeHandler with required dependencies. */
    public RaiseDisputeHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /recovery/dispute — raises a dispute and pauses the session. */
    @PostMapping
    public ResponseEntity<ApiResponse<RaiseDisputeResponse>> raiseDispute(
            @RequestBody @Valid RaiseDisputeRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();

        List<RecoverySession> sessionRows = dbClient.query(SELECT_SESSION,
                RecoverySessionRowMapper.INSTANCE, request.sessionId());
        if (sessionRows.isEmpty()) {
            throw AppException.notFound("recovery_session");
        }
        RecoverySession session = sessionRows.get(0);

        if (!partyId.equals(session.creatorId())) {
            List<RecoveryBlobLayer> authRows = dbClient.query(SELECT_AUTH_LAYER,
                    RecoveryBlobLayerRowMapper.INSTANCE, session.blobId(), partyId);
            if (authRows.isEmpty()) {
                throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Not authorized for this session");
            }
        }

        if ("completed".equals(session.status())) {
            throw new AppException(ErrorCode.CONFLICT, "Session already completed.");
        }
        if ("disputed".equals(session.status())) {
            throw new AppException(ErrorCode.CONFLICT, "Dispute already raised.");
        }

        String disputeId = CsprngUtil.randomUlid();
        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_DISPUTE, disputeId, session.sessionId(), partyId,
                    jwt.partyType().name().toLowerCase(), request.reason());
            dbClient.execute(UPDATE_SESSION_DISPUTED, session.sessionId());
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.DISPUTE_RAISED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(jwt.partyType()).targetId(disputeId)
                .build());

        log.info("Dispute raised: disputeId={} sessionId={} partyId={}",
                disputeId, session.sessionId(), partyId);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(new RaiseDisputeResponse(
                disputeId, "open",
                "Dispute raised. Recovery session paused pending admin review."), requestId));
    }

    private record RaiseDisputeResponse(String disputeId, String status, String message) {}
}
