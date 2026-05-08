package in.deathtrap.locker.routes.locker;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.AssetCatalogue;
import in.deathtrap.locker.config.JwtService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles locker initialisation for a newly registered creator. */
@RestController
@RequestMapping("/locker")
public class InitLockerHandler {

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String INSERT_LOCKER =
            "INSERT INTO locker_meta (locker_id, user_id, completeness_pct, online_pct, offline_pct, " +
            "blob_built, created_at, updated_at) VALUES (?, ?, 0, 0, 0, FALSE, ?, ?)";
    private static final String INSERT_ASSET =
            "INSERT INTO asset_index (asset_id, locker_id, category_code, asset_type, status, " +
            "created_at, updated_at) VALUES (?, ?, ?, ?::asset_type_enum, 'empty'::asset_status_enum, ?, ?)";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs InitLockerHandler with required dependencies. */
    public InitLockerHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /locker/init — creates locker_meta and 24 asset_index rows atomically. */
    @PostMapping("/init")
    public ResponseEntity<ApiResponse<InitLockerResponse>> initLocker(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        List<String> existing = dbClient.query(SELECT_LOCKER, STRING_MAPPER, creatorId);
        if (!existing.isEmpty()) {
            throw AppException.conflict("Locker already initialized");
        }

        String lockerId = CsprngUtil.randomUlid();
        Instant now = Instant.now();

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_LOCKER, lockerId, creatorId, now, now);
            for (AssetCatalogue.AssetEntry entry : AssetCatalogue.ALL) {
                dbClient.execute(INSERT_ASSET,
                        CsprngUtil.randomUlid(), lockerId,
                        entry.categoryCode(), entry.assetType().name().toLowerCase(),
                        now, now);
            }
            return null;
        });

        auditWriter.write(AuditWritePayload.builder(AuditEventType.LOCKER_CREATED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(lockerId).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(
                ApiResponse.ok(new InitLockerResponse(lockerId, AssetCatalogue.ALL.size()), requestId));
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

    private record InitLockerResponse(String lockerId, int assetCount) {}
}
