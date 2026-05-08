package in.deathtrap.locker.routes.nominee;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeUnassignRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.NomineeAssignmentRowMapper;
import in.deathtrap.locker.rowmapper.NomineeAssignmentRowMapper.NomineeAssignment;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles soft-deletion of a nominee assignment from a locker asset. */
@RestController
@RequestMapping("/locker/nominee")
public class UnassignNomineeHandler {

    private static final String SELECT_ASSIGNMENT =
            "SELECT assignment_id, asset_id, locker_id, nominee_id, official_nomination_status, " +
            "display_order, notes, assigned_at, removed_at, created_at, updated_at " +
            "FROM nominee_assignments WHERE assignment_id = ? AND removed_at IS NULL LIMIT 1";
    private static final String SELECT_ASSET =
            "SELECT asset_id FROM asset_index WHERE asset_id = ? AND locker_id = ? LIMIT 1";
    private static final String SOFT_DELETE =
            "UPDATE nominee_assignments SET removed_at = NOW(), updated_at = NOW() " +
            "WHERE assignment_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs UnassignNomineeHandler with required dependencies. */
    public UnassignNomineeHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** DELETE /locker/nominee/unassign — soft-deletes a nominee assignment. */
    @DeleteMapping("/unassign")
    public ResponseEntity<Void> unassignNominee(
            @RequestBody @Valid NomineeUnassignRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        List<NomineeAssignment> assignmentRows = dbClient.query(
                SELECT_ASSIGNMENT, NomineeAssignmentRowMapper.INSTANCE, request.assignmentId());
        if (assignmentRows.isEmpty()) {
            throw AppException.notFound("assignment");
        }
        NomineeAssignment assignment = assignmentRows.get(0);

        List<String> assetLockerId = dbClient.query(
                "SELECT locker_id FROM locker_meta WHERE user_id = ?",
                STRING_MAPPER, creatorId);
        if (assetLockerId.isEmpty() || !assetLockerId.get(0).equals(assignment.lockerId())) {
            throw AppException.forbidden();
        }

        List<String> assetRows = dbClient.query(SELECT_ASSET, STRING_MAPPER,
                assignment.assetId(), assignment.lockerId());
        if (assetRows.isEmpty()) {
            throw AppException.notFound("asset");
        }

        dbClient.execute(SOFT_DELETE, request.assignmentId());

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_UNASSIGNED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(request.assignmentId()).build());

        return ResponseEntity.noContent().build();
    }

    private JwtPayload validateCreatorJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        return jwt;
    }
}
