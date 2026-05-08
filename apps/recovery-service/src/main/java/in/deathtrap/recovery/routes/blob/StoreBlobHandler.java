package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.BlobLayerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.StoreBlobRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.service.BlobRebuildLogService;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/** Handles storing a layered recovery blob from the creator. */
@RestController
@RequestMapping("/recovery/blob")
public class StoreBlobHandler {

    private static final Logger log = LoggerFactory.getLogger(StoreBlobHandler.class);

    private static final String SELECT_NOMINEES =
            "SELECT nominee_id FROM nominees WHERE creator_id = ? AND status = 'active' " +
            "ORDER BY registration_order ASC";
    private static final String SELECT_PUBKEY =
            "SELECT is_active FROM party_public_keys " +
            "WHERE pubkey_id = ? AND party_id = ? AND party_type = ?::party_type_enum";
    private static final String SELECT_ACTIVE_BLOB =
            "SELECT blob_id FROM recovery_blobs WHERE creator_id = ? AND status = 'active' LIMIT 1";
    private static final String SUPERSEDE_BLOB =
            "UPDATE recovery_blobs SET status = 'superseded', updated_at = NOW() " +
            "WHERE creator_id = ? AND status = 'active'";
    private static final String INSERT_BLOB =
            "INSERT INTO recovery_blobs (blob_id, creator_id, s3_key, layer_count, status, " +
            "built_at, created_at) VALUES (?, ?, ?, ?, 'active', NOW(), NOW())";
    private static final String INSERT_LAYER =
            "INSERT INTO recovery_blob_layers (layer_id, blob_id, layer_order, party_id, " +
            "party_type, pubkey_id, key_fingerprint, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, NOW())";
    private static final String UPDATE_LOCKER_BLOB_BUILT =
            "UPDATE locker_meta SET blob_built = TRUE, updated_at = NOW() WHERE user_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Boolean> BOOL_MAPPER = (rs, row) -> rs.getBoolean(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Client s3Client;
    private final BlobRebuildLogService rebuildLogService;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    @Value("${KMS_KEY_ID:}")
    private String kmsKeyId;

    /** Constructs StoreBlobHandler with required dependencies. */
    public StoreBlobHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter,
            S3Client s3Client, BlobRebuildLogService rebuildLogService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Client = s3Client;
        this.rebuildLogService = rebuildLogService;
    }

    /** POST /recovery/blob — validates layers, uploads to S3, records DB rows atomically. */
    @PostMapping
    public ResponseEntity<ApiResponse<StoreBlobResponse>> storeBlob(
            @RequestBody @Valid StoreBlobRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        if (request.layers().isEmpty()) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "Recovery blob must have at least 1 layer (lawyer)");
        }

        for (BlobLayerRequest layer : request.layers()) {
            List<Boolean> keyRows = dbClient.query(SELECT_PUBKEY, BOOL_MAPPER,
                    layer.pubkeyId(), layer.partyId(), layer.partyType());
            if (keyRows.isEmpty() || !keyRows.get(0)) {
                throw new AppException(ErrorCode.VALIDATION_FAILED,
                        "Key version mismatch for party " + layer.partyId() + ". Key may have rotated.");
            }
        }

        List<String> oldBlobRows = dbClient.query(SELECT_ACTIVE_BLOB, STRING_MAPPER, creatorId);
        String oldBlobId = oldBlobRows.isEmpty() ? null : oldBlobRows.get(0);

        String blobId = CsprngUtil.randomUlid();
        String s3Key = "recovery/" + creatorId + "/" + blobId;
        putToS3OrDev(blobId, s3Key, request.encryptedBlobB64());

        dbClient.withTransaction(status -> {
            if (oldBlobId != null) {
                dbClient.execute(SUPERSEDE_BLOB, creatorId);
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.RECOVERY_BLOB_SUPERSEDED, AuditResult.SUCCESS)
                        .actorId(creatorId).actorType(PartyType.CREATOR).targetId(oldBlobId)
                        .build());
            }
            dbClient.execute(INSERT_BLOB, blobId, creatorId, s3Key, request.layers().size());
            for (int i = 0; i < request.layers().size(); i++) {
                BlobLayerRequest layer = request.layers().get(i);
                dbClient.execute(INSERT_LAYER,
                        CsprngUtil.randomUlid(), blobId, i + 1,
                        layer.partyId(), layer.partyType(), layer.pubkeyId(), layer.keyFingerprint());
            }
            dbClient.execute(UPDATE_LOCKER_BLOB_BUILT, creatorId);
            return null;
        });

        rebuildLogService.log(creatorId, oldBlobId, blobId, request.rebuildReason(),
                creatorId, "creator");

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.RECOVERY_BLOB_STORED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(blobId)
                .metadataJson(Map.of("layerCount", request.layers().size(),
                        "rebuildReason", request.rebuildReason()))
                .build());

        log.info("Recovery blob stored: creatorId={} blobId={} layers={}", creatorId, blobId,
                request.layers().size());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new StoreBlobResponse(blobId, request.layers().size(), Instant.now()), requestId));
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
        s3Client.putObject(builder.build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(bytes));
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

    private record StoreBlobResponse(String blobId, int layerCount, Instant builtAt) {}
}
