package in.deathtrap.locker.routes.sync;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeAssignmentUpdate;
import in.deathtrap.common.types.dto.SyncPushRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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

/** Handles WatermelonDB push sync — applies nominee assignment updates from the mobile client. */
@RestController
@RequestMapping("/locker/sync")
public class SyncPushHandler {

    private static final Logger log = LoggerFactory.getLogger(SyncPushHandler.class);

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSIGNMENT =
            "SELECT assignment_id FROM nominee_assignments " +
            "WHERE assignment_id = ? AND locker_id = ? AND removed_at IS NULL LIMIT 1";
    private static final String UPDATE_ASSIGNMENT =
            "UPDATE nominee_assignments SET " +
            "official_nomination_status = COALESCE(?, official_nomination_status), " +
            "display_order = COALESCE(?, display_order), " +
            "notes = COALESCE(?, notes), " +
            "updated_at = NOW() WHERE assignment_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs SyncPushHandler with required dependencies. */
    public SyncPushHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /locker/sync — applies mobile-side nominee assignment changes to the server. */
    @PostMapping
    public ResponseEntity<ApiResponse<SyncPushResponse>> syncPush(
            @RequestBody @Valid SyncPushRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        String creatorId = jwt.sub();

        List<String> lockerRows = dbClient.query(SELECT_LOCKER, STRING_MAPPER, creatorId);
        if (lockerRows.isEmpty()) {
            throw AppException.notFound("locker");
        }
        String lockerId = lockerRows.get(0);

        int appliedCount = 0;
        List<NomineeAssignmentUpdate> updates = request.changes().nomineeAssignments();
        if (updates != null) {
            for (NomineeAssignmentUpdate update : updates) {
                List<String> assignmentRows = dbClient.query(
                        SELECT_ASSIGNMENT, STRING_MAPPER, update.assignmentId(), lockerId);
                if (assignmentRows.isEmpty()) {
                    log.warn("Push ignored unknown or foreign assignment: {}", update.assignmentId());
                    continue;
                }
                dbClient.execute(UPDATE_ASSIGNMENT,
                        update.officialNominationStatus(),
                        update.displayOrder(),
                        update.notes(),
                        update.assignmentId());

                if (update.officialNominationStatus() != null) {
                    auditWriter.write(AuditWritePayload
                            .builder(AuditEventType.OFFICIAL_NOMINATION_UPDATED, AuditResult.SUCCESS)
                            .actorId(creatorId).actorType(PartyType.CREATOR)
                            .targetId(update.assignmentId())
                            .metadataJson(Map.of("newStatus", update.officialNominationStatus()))
                            .build());
                }
                appliedCount++;
            }
        }

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new SyncPushResponse(Instant.now().toEpochMilli(), appliedCount), requestId));
    }

    private record SyncPushResponse(long timestamp, int appliedCount) {}
}
