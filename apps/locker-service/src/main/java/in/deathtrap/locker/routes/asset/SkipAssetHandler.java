package in.deathtrap.locker.routes.asset;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import in.deathtrap.locker.service.CompletenessCalculator;
import in.deathtrap.locker.service.CompletenessCalculator.CompletenessScore;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles marking an empty asset category as intentionally skipped. */
@RestController
@RequestMapping("/locker/asset")
public class SkipAssetHandler {

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSET =
            "SELECT asset_id, locker_id, category_code, asset_type, status, created_at, updated_at " +
            "FROM asset_index WHERE asset_id = ? AND locker_id = ? LIMIT 1";
    private static final String UPDATE_SKIP =
            "UPDATE asset_index SET status = 'skipped'::asset_status_enum, updated_at = NOW() " +
            "WHERE asset_id = ?";
    private static final String UPDATE_COMPLETENESS =
            "UPDATE locker_meta SET completeness_pct = ?, online_pct = ?, offline_pct = ?, " +
            "last_saved_at = NOW(), updated_at = NOW() WHERE locker_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final CompletenessCalculator completenessCalculator;

    /** Constructs SkipAssetHandler with required dependencies. */
    public SkipAssetHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, CompletenessCalculator completenessCalculator) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.completenessCalculator = completenessCalculator;
    }

    /** PATCH /locker/asset/{assetId}/skip — marks an empty asset as skipped. */
    @PatchMapping("/{assetId}/skip")
    public ResponseEntity<ApiResponse<SkipAssetResponse>> skipAsset(
            @PathVariable String assetId,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        List<String> lockerRows = dbClient.query(SELECT_LOCKER, STRING_MAPPER, creatorId);
        if (lockerRows.isEmpty()) {
            throw AppException.notFound("locker");
        }
        String lockerId = lockerRows.get(0);

        List<AssetIndex> assetRows = dbClient.query(SELECT_ASSET, AssetIndexRowMapper.INSTANCE, assetId, lockerId);
        if (assetRows.isEmpty()) {
            throw AppException.notFound("asset");
        }
        AssetIndex asset = assetRows.get(0);

        if ("filled".equals(asset.status())) {
            throw AppException.conflict("Cannot skip an asset with uploaded data. Delete the blob first.");
        }

        dbClient.withTransaction(status -> {
            dbClient.execute(UPDATE_SKIP, assetId);
            CompletenessScore score = completenessCalculator.recalculate(lockerId);
            dbClient.execute(UPDATE_COMPLETENESS,
                    score.overall(), score.onlinePct(), score.offlinePct(), lockerId);
            return null;
        });

        CompletenessScore finalScore = completenessCalculator.recalculate(lockerId);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.ASSET_SKIPPED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(assetId).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new SkipAssetResponse(assetId, "skipped", finalScore.overall()), requestId));
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

    private record SkipAssetResponse(String assetId, String status, int completenessScore) {}
}
