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
import in.deathtrap.locker.service.ClosureWriteGate;
import in.deathtrap.locker.service.CompletenessCalculator;
import in.deathtrap.locker.service.CompletenessCalculator.CompletenessScore;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles reverting an intentionally skipped asset back to empty. */
@RestController
@RequestMapping("/locker/asset")
public class UnskipAssetHandler {

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSET =
            "SELECT asset_id, locker_id, category_code, asset_type, status, created_at, updated_at " +
            "FROM asset_index WHERE locker_id = ? AND category_code = ? LIMIT 1";
    private static final String UPDATE_UNSKIP =
            "UPDATE asset_index SET status = 'empty'::asset_status_enum, updated_at = NOW() " +
            "WHERE asset_id = ?";
    private static final String UPDATE_COMPLETENESS =
            "UPDATE locker_meta SET completeness_pct = ?, online_pct = ?, offline_pct = ?, " +
            "last_saved_at = NOW(), updated_at = NOW() WHERE locker_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final CompletenessCalculator completenessCalculator;
    private final ClosureWriteGate closureWriteGate;

    public UnskipAssetHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, CompletenessCalculator completenessCalculator,
            ClosureWriteGate closureWriteGate) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.completenessCalculator = completenessCalculator;
        this.closureWriteGate = closureWriteGate;
    }

    /** PATCH /locker/asset/{categoryCode}/unskip — flips skipped back to empty. */
    @PatchMapping("/{categoryCode}/unskip")
    public ResponseEntity<ApiResponse<UnskipAssetResponse>> unskipAsset(
            @PathVariable String categoryCode,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        closureWriteGate.assertWritesAllowed(creatorId);

        List<String> lockerRows = dbClient.query(SELECT_LOCKER, STRING_MAPPER, creatorId);
        if (lockerRows.isEmpty()) {
            throw AppException.notFound("locker");
        }
        String lockerId = lockerRows.get(0);

        List<AssetIndex> assetRows = dbClient.query(SELECT_ASSET, AssetIndexRowMapper.INSTANCE, lockerId, categoryCode);
        if (assetRows.isEmpty()) {
            throw AppException.notFound("asset");
        }
        AssetIndex asset = assetRows.get(0);

        if (!"skipped".equals(asset.status())) {
            throw AppException.conflict("Asset is not currently skipped (status=" + asset.status() + ")");
        }

        dbClient.withTransaction(status -> {
            dbClient.execute(UPDATE_UNSKIP, asset.assetId());
            CompletenessScore score = completenessCalculator.recalculate(lockerId);
            dbClient.execute(UPDATE_COMPLETENESS,
                    score.overall(), score.onlinePct(), score.offlinePct(), lockerId);
            return null;
        });

        auditWriter.write(AuditWritePayload.builder(AuditEventType.ASSET_SKIPPED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(asset.assetId())
                .metadataJson(Map.of("categoryCode", categoryCode, "action", "unskip"))
                .build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new UnskipAssetResponse(categoryCode, "empty"), requestId));
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

    private record UnskipAssetResponse(String categoryCode, String status) {}
}
