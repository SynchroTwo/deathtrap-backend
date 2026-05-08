package in.deathtrap.locker.routes.blob;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.UploadBlobRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import in.deathtrap.locker.service.CompletenessCalculator;
import in.deathtrap.locker.service.CompletenessCalculator.CompletenessScore;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/** Handles encrypted blob uploads to S3 with completeness tracking. */
@RestController
@RequestMapping("/locker/blob")
public class UploadBlobHandler {

    private static final Logger log = LoggerFactory.getLogger(UploadBlobHandler.class);
    private static final long MAX_BLOB_BYTES = 100_000_000L;
    private static final int HASH_HEX_LENGTH = 64;

    private static final String SELECT_LOCKER =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ASSET =
            "SELECT asset_id, locker_id, category_code, asset_type, status, created_at, updated_at " +
            "FROM asset_index WHERE locker_id = ? AND category_code = ? LIMIT 1";
    private static final String SUPERSEDE_BLOBS =
            "UPDATE blob_versions SET is_current = FALSE, updated_at = NOW() " +
            "WHERE asset_id = ? AND is_current = TRUE";
    private static final String INSERT_BLOB =
            "INSERT INTO blob_versions (blob_id, asset_id, locker_id, s3_key, size_bytes, " +
            "content_hash_sha256, schema_version, is_current, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?)";
    private static final String UPDATE_ASSET_FILLED =
            "UPDATE asset_index SET status = 'filled'::asset_status_enum, updated_at = NOW() " +
            "WHERE asset_id = ?";
    private static final String UPDATE_COMPLETENESS =
            "UPDATE locker_meta SET completeness_pct = ?, online_pct = ?, offline_pct = ?, " +
            "last_saved_at = NOW(), updated_at = NOW() WHERE locker_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Client s3Client;
    private final CompletenessCalculator completenessCalculator;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    @Value("${KMS_KEY_ID:}")
    private String kmsKeyId;

    /** Constructs UploadBlobHandler with required dependencies. */
    public UploadBlobHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter,
            S3Client s3Client, CompletenessCalculator completenessCalculator) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Client = s3Client;
        this.completenessCalculator = completenessCalculator;
    }

    /** PUT /locker/blob/{categoryCode} — validates, uploads to S3, records blob_versions row. */
    @PutMapping("/{categoryCode}")
    public ResponseEntity<ApiResponse<UploadBlobResponse>> uploadBlob(
            @PathVariable String categoryCode,
            @RequestBody @Valid UploadBlobRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        validateRequest(request);

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

        String blobId = CsprngUtil.randomUlid();
        String s3Key = "locker/" + lockerId + "/" + categoryCode + "/" + blobId;
        putToS3OrDev(blobId, s3Key, request.encryptedBlobB64());

        Instant now = Instant.now();
        int[] scoreBuf = {0};
        dbClient.withTransaction(status -> {
            dbClient.execute(SUPERSEDE_BLOBS, asset.assetId());
            dbClient.execute(INSERT_BLOB, blobId, asset.assetId(), lockerId, s3Key,
                    request.sizeBytes(), request.contentHashSha256(), request.schemaVersion(), now);
            dbClient.execute(UPDATE_ASSET_FILLED, asset.assetId());
            CompletenessScore score = completenessCalculator.recalculate(lockerId);
            scoreBuf[0] = score.overall();
            dbClient.execute(UPDATE_COMPLETENESS,
                    score.overall(), score.onlinePct(), score.offlinePct(), lockerId);
            return null;
        });

        auditWriter.write(AuditWritePayload.builder(AuditEventType.BLOB_SAVED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(asset.assetId())
                .metadataJson(Map.of("categoryCode", categoryCode,
                        "sizeBytes", request.sizeBytes(), "blobVersionId", blobId))
                .build());

        log.info("Blob uploaded: lockerId={} categoryCode={} blobId={}", lockerId, categoryCode, blobId);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new UploadBlobResponse(blobId, categoryCode, request.sizeBytes(), now, scoreBuf[0]),
                requestId));
    }

    private void putToS3OrDev(String blobId, String s3Key, String encryptedBlobB64) {
        if (s3BucketName == null || s3BucketName.isBlank()) {
            log.warn("[DEV] S3 upload skipped for blobId={}", blobId);
            return;
        }
        byte[] bytes = Base64.getDecoder().decode(encryptedBlobB64);
        PutObjectRequest.Builder builder = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key(s3Key)
                .serverSideEncryption(ServerSideEncryption.AWS_KMS);
        if (kmsKeyId != null && !kmsKeyId.isBlank()) {
            builder.ssekmsKeyId(kmsKeyId);
        }
        s3Client.putObject(builder.build(), software.amazon.awssdk.core.sync.RequestBody.fromBytes(bytes));
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

    private void validateRequest(UploadBlobRequest request) {
        if (request.sizeBytes() >= MAX_BLOB_BYTES) {
            throw AppException.validationFailed(Map.of("sizeBytes", "Must be less than 100MB"));
        }
        if (request.contentHashSha256() == null || request.contentHashSha256().length() != HASH_HEX_LENGTH
                || !request.contentHashSha256().matches("[0-9a-fA-F]+")) {
            throw AppException.validationFailed(Map.of("contentHashSha256", "Must be exactly 64 hex characters"));
        }
    }

    private record UploadBlobResponse(
            String blobVersionId,
            String categoryCode,
            long sizeBytes,
            Instant uploadedAt,
            int completenessScore
    ) {}
}
