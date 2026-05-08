package in.deathtrap.locker.routes.nominee;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeAssignRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles assigning a nominee to a specific locker asset. */
@RestController
@RequestMapping("/locker/nominee")
public class AssignNomineeHandler {

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSET =
            "SELECT asset_id FROM asset_index WHERE asset_id = ? AND locker_id = ? LIMIT 1";
    private static final String SELECT_NOMINEE =
            "SELECT nominee_id FROM nominees WHERE nominee_id = ? AND creator_id = ? " +
            "AND status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_EXISTING_ASSIGNMENT =
            "SELECT assignment_id FROM nominee_assignments " +
            "WHERE asset_id = ? AND nominee_id = ? AND removed_at IS NULL LIMIT 1";
    private static final String SELECT_NEXT_ORDER =
            "SELECT COALESCE(MAX(display_order), 0) + 1 FROM nominee_assignments " +
            "WHERE asset_id = ? AND removed_at IS NULL";
    private static final String INSERT_ASSIGNMENT =
            "INSERT INTO nominee_assignments (assignment_id, asset_id, locker_id, nominee_id, " +
            "official_nomination_status, display_order, assigned_at, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, 'unknown', ?, NOW(), NOW(), NOW())";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Long> LONG_MAPPER = (rs, row) -> rs.getLong(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs AssignNomineeHandler with required dependencies. */
    public AssignNomineeHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /locker/nominee/assign — adds a nominee assignment for an asset. */
    @PostMapping("/assign")
    public ResponseEntity<ApiResponse<AssignResponse>> assignNominee(
            @RequestBody @Valid NomineeAssignRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        List<String> lockerRows = dbClient.query(SELECT_LOCKER, STRING_MAPPER, creatorId);
        if (lockerRows.isEmpty()) {
            throw AppException.notFound("locker");
        }
        String lockerId = lockerRows.get(0);

        List<String> assetRows = dbClient.query(SELECT_ASSET, STRING_MAPPER, request.assetId(), lockerId);
        if (assetRows.isEmpty()) {
            throw AppException.notFound("asset");
        }

        List<String> nomineeRows = dbClient.query(SELECT_NOMINEE, STRING_MAPPER,
                request.nomineeId(), creatorId);
        if (nomineeRows.isEmpty()) {
            throw AppException.notFound("nominee");
        }

        List<String> existingRows = dbClient.query(SELECT_EXISTING_ASSIGNMENT, STRING_MAPPER,
                request.assetId(), request.nomineeId());
        if (!existingRows.isEmpty()) {
            throw AppException.conflict("Nominee already assigned to this asset");
        }

        List<Long> orderRows = dbClient.query(SELECT_NEXT_ORDER, LONG_MAPPER, request.assetId());
        long displayOrder = orderRows.isEmpty() ? 1L : orderRows.get(0);

        String assignmentId = CsprngUtil.randomUlid();
        dbClient.execute(INSERT_ASSIGNMENT, assignmentId, request.assetId(), lockerId,
                request.nomineeId(), displayOrder);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_ASSIGNED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(assignmentId).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(new AssignResponse(assignmentId), requestId));
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

    private record AssignResponse(String assignmentId) {}
}
