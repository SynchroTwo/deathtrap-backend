package in.deathtrap.locker.routes.sync;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import in.deathtrap.locker.rowmapper.BlobVersionRowMapper;
import in.deathtrap.locker.rowmapper.BlobVersionRowMapper.BlobVersion;
import in.deathtrap.locker.rowmapper.NomineeAssignmentRowMapper;
import in.deathtrap.locker.rowmapper.NomineeAssignmentRowMapper.NomineeAssignment;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Handles WatermelonDB incremental pull sync for locker state. */
@RestController
@RequestMapping("/locker/sync")
public class SyncPullHandler {

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSETS_CHANGED =
            "SELECT asset_id, locker_id, category_code, asset_type, status, created_at, updated_at " +
            "FROM asset_index WHERE locker_id = ? AND (created_at > ? OR updated_at > ?)";
    private static final String SELECT_ASSIGNMENTS_CHANGED =
            "SELECT assignment_id, asset_id, locker_id, nominee_id, official_nomination_status, " +
            "display_order, notes, assigned_at, removed_at, created_at, updated_at " +
            "FROM nominee_assignments WHERE locker_id = ? AND (created_at > ? OR updated_at > ?)";
    private static final String SELECT_BLOBS_CHANGED =
            "SELECT bv.blob_id, bv.asset_id, bv.locker_id, bv.s3_key, bv.size_bytes, " +
            "bv.content_hash_sha256, bv.schema_version, bv.is_current, bv.created_at, bv.updated_at " +
            "FROM blob_versions bv " +
            "JOIN asset_index ai ON bv.asset_id = ai.asset_id " +
            "WHERE ai.locker_id = ? AND bv.is_current = TRUE AND bv.created_at > ?";
    private static final String SELECT_COMPLETENESS =
            "SELECT completeness_pct FROM locker_meta WHERE locker_id = ? LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);

    private final DbClient dbClient;
    private final JwtService jwtService;

    /** Constructs SyncPullHandler with required dependencies. */
    public SyncPullHandler(DbClient dbClient, JwtService jwtService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
    }

    /** GET /locker/sync — returns WatermelonDB-format delta since lastPulledAt. */
    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> syncPull(
            @RequestParam(defaultValue = "0") long lastPulledAt,
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

        Instant since = Instant.ofEpochMilli(lastPulledAt);
        Timestamp sinceTs = Timestamp.from(since);

        List<AssetIndex> changedAssets = dbClient.query(
                SELECT_ASSETS_CHANGED, AssetIndexRowMapper.INSTANCE, lockerId, sinceTs, sinceTs);

        List<NomineeAssignment> changedAssignments = dbClient.query(
                SELECT_ASSIGNMENTS_CHANGED, NomineeAssignmentRowMapper.INSTANCE, lockerId, sinceTs, sinceTs);

        List<BlobVersion> changedBlobs = dbClient.query(
                SELECT_BLOBS_CHANGED, BlobVersionRowMapper.INSTANCE, lockerId, sinceTs);

        List<Integer> completenessRows = dbClient.query(SELECT_COMPLETENESS, INT_MAPPER, lockerId);
        int completenessScore = completenessRows.isEmpty() ? 0 : completenessRows.get(0);

        Map<String, Object> assetChanges = buildAssetChanges(changedAssets, since);
        Map<String, Object> assignmentChanges = buildAssignmentChanges(changedAssignments, since);
        Map<String, Object> blobChanges = buildBlobChanges(changedBlobs, since);

        Map<String, Object> changes = new LinkedHashMap<>();
        changes.put("asset_index", assetChanges);
        changes.put("nominee_assignments", assignmentChanges);
        changes.put("blob_versions", blobChanges);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("changes", changes);
        body.put("timestamp", Instant.now().toEpochMilli());
        body.put("completenessScore", completenessScore);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    private Map<String, Object> buildAssetChanges(List<AssetIndex> assets, Instant since) {
        List<Map<String, Object>> created = new ArrayList<>();
        List<Map<String, Object>> updated = new ArrayList<>();
        for (AssetIndex a : assets) {
            Map<String, Object> row = assetToMap(a);
            if (a.createdAt().isAfter(since)) {
                created.add(row);
            } else {
                updated.add(row);
            }
        }
        Map<String, Object> result = new HashMap<>();
        result.put("created", created);
        result.put("updated", updated);
        result.put("deleted", List.of());
        return result;
    }

    private Map<String, Object> buildAssignmentChanges(List<NomineeAssignment> assignments, Instant since) {
        List<Map<String, Object>> created = new ArrayList<>();
        List<Map<String, Object>> updated = new ArrayList<>();
        List<String> deleted = new ArrayList<>();
        for (NomineeAssignment a : assignments) {
            if (a.removedAt() != null) {
                deleted.add(a.assignmentId());
            } else if (a.createdAt().isAfter(since)) {
                created.add(assignmentToMap(a));
            } else {
                updated.add(assignmentToMap(a));
            }
        }
        Map<String, Object> result = new HashMap<>();
        result.put("created", created);
        result.put("updated", updated);
        result.put("deleted", deleted);
        return result;
    }

    private Map<String, Object> buildBlobChanges(List<BlobVersion> blobs, Instant since) {
        List<Map<String, Object>> created = new ArrayList<>();
        List<Map<String, Object>> updated = new ArrayList<>();
        for (BlobVersion b : blobs) {
            Map<String, Object> row = blobToMap(b);
            if (b.createdAt().isAfter(since)) {
                created.add(row);
            } else {
                updated.add(row);
            }
        }
        Map<String, Object> result = new HashMap<>();
        result.put("created", created);
        result.put("updated", updated);
        result.put("deleted", List.of());
        return result;
    }

    private static Map<String, Object> assetToMap(AssetIndex a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("asset_id", a.assetId());
        m.put("locker_id", a.lockerId());
        m.put("category_code", a.categoryCode());
        m.put("asset_type", a.assetType());
        m.put("status", a.status());
        m.put("created_at", a.createdAt().toEpochMilli());
        m.put("updated_at", a.updatedAt().toEpochMilli());
        return m;
    }

    private static Map<String, Object> assignmentToMap(NomineeAssignment a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("assignment_id", a.assignmentId());
        m.put("asset_id", a.assetId());
        m.put("locker_id", a.lockerId());
        m.put("nominee_id", a.nomineeId());
        m.put("official_nomination_status", a.officialNominationStatus());
        m.put("display_order", a.displayOrder());
        m.put("notes", a.notes());
        m.put("assigned_at", a.assignedAt().toEpochMilli());
        m.put("removed_at", a.removedAt() != null ? a.removedAt().toEpochMilli() : null);
        m.put("created_at", a.createdAt().toEpochMilli());
        m.put("updated_at", a.updatedAt() != null ? a.updatedAt().toEpochMilli() : null);
        return m;
    }

    private static Map<String, Object> blobToMap(BlobVersion b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("blob_id", b.blobId());
        m.put("asset_id", b.assetId());
        m.put("locker_id", b.lockerId());
        m.put("s3_key", b.s3Key());
        m.put("size_bytes", b.sizeBytes());
        m.put("content_hash_sha256", b.contentHashSha256());
        m.put("schema_version", b.schemaVersion());
        m.put("is_current", b.isCurrent());
        m.put("created_at", b.createdAt().toEpochMilli());
        m.put("updated_at", b.updatedAt() != null ? b.updatedAt().toEpochMilli() : null);
        return m;
    }
}
