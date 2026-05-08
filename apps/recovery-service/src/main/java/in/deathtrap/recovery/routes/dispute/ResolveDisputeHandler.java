package in.deathtrap.recovery.routes.dispute;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.ResolveDisputeRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.DisputeRowMapper;
import in.deathtrap.recovery.rowmapper.DisputeRowMapper.Dispute;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles admin resolution of a raised dispute. */
@RestController
@RequestMapping("/recovery/dispute")
public class ResolveDisputeHandler {

    private static final Logger log = LoggerFactory.getLogger(ResolveDisputeHandler.class);

    private static final String SELECT_DISPUTE =
            "SELECT dispute_id, session_id, raised_by, raised_by_type, reason, status, " +
            "raised_at, resolved_by, resolved_at, resolution_notes, created_at " +
            "FROM dispute_log WHERE dispute_id = ? LIMIT 1";
    private static final String UPDATE_DISPUTE =
            "UPDATE dispute_log SET status = ?, resolved_by = ?, resolved_at = NOW(), " +
            "resolution_notes = ?, updated_at = NOW() WHERE dispute_id = ?";
    private static final String UPDATE_SESSION_STATUS =
            "UPDATE recovery_sessions SET status = ?, updated_at = NOW() WHERE session_id = ?";

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs ResolveDisputeHandler with required dependencies. */
    public ResolveDisputeHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** PATCH /recovery/dispute/{disputeId} — admin resolves the dispute and updates session. */
    @PatchMapping("/{disputeId}")
    public ResponseEntity<ApiResponse<ResolveDisputeResponse>> resolveDispute(
            @PathVariable String disputeId,
            @RequestBody @Valid ResolveDisputeRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String adminId = jwt.sub();

        if (jwt.partyType() != PartyType.ADMIN) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Only admins can resolve disputes");
        }

        List<Dispute> disputeRows = dbClient.query(SELECT_DISPUTE, DisputeRowMapper.INSTANCE, disputeId);
        if (disputeRows.isEmpty()) {
            throw AppException.notFound("dispute");
        }
        Dispute dispute = disputeRows.get(0);

        if (!"open".equals(dispute.status()) && !"under_review".equals(dispute.status())) {
            throw new AppException(ErrorCode.CONFLICT, "Dispute is already resolved");
        }

        String newSessionStatus = switch (request.resolution()) {
            case "resolved_halt" -> "cancelled";
            default -> "in_progress";
        };
        boolean sessionResumed = !"cancelled".equals(newSessionStatus);

        dbClient.withTransaction(status -> {
            dbClient.execute(UPDATE_DISPUTE, request.resolution(), adminId,
                    request.notes(), disputeId);
            dbClient.execute(UPDATE_SESSION_STATUS, newSessionStatus, dispute.sessionId());
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.DISPUTE_RESOLVED, AuditResult.SUCCESS)
                .actorId(adminId).actorType(PartyType.ADMIN).targetId(disputeId)
                .metadataJson(Map.of("resolution", request.resolution(),
                        "sessionResumed", sessionResumed))
                .build());

        log.info("Dispute resolved: disputeId={} resolution={} newSessionStatus={}",
                disputeId, request.resolution(), newSessionStatus);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(new ResolveDisputeResponse(
                disputeId, request.resolution(), newSessionStatus), requestId));
    }

    private record ResolveDisputeResponse(String disputeId, String resolution, String sessionStatus) {}
}
