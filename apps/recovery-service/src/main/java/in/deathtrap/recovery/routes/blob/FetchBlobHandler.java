package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper.RecoveryBlob;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;

/** Handles fetching the active recovery blob for any authorized party. */
@RestController
@RequestMapping("/recovery/blob")
public class FetchBlobHandler {

    private static final Logger log = LoggerFactory.getLogger(FetchBlobHandler.class);

    private static final String SELECT_CREATOR_ID_FOR_NOMINEE =
            "SELECT creator_id FROM nominees WHERE nominee_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_CREATOR_ID_FOR_LAWYER =
            "SELECT rb.creator_id FROM recovery_blobs rb " +
            "JOIN recovery_blob_layers rbl ON rbl.blob_id = rb.blob_id " +
            "WHERE rbl.party_id = ? AND rbl.party_type = 'lawyer' AND rb.status = 'active' LIMIT 1";
    private static final String SELECT_ACTIVE_BLOB =
            "SELECT blob_id, creator_id, s3_key, layer_count, status, built_at, created_at " +
            "FROM recovery_blobs WHERE creator_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_MY_LAYER =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND party_id = ? AND party_type = ?::party_type_enum LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Client s3Client;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    /** Constructs FetchBlobHandler with required dependencies. */
    public FetchBlobHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, S3Client s3Client) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Client = s3Client;
    }

    /** GET /recovery/blob — resolves creator, fetches active blob, returns encrypted bytes. */
    @GetMapping
    public ResponseEntity<ApiResponse<FetchBlobResponse>> fetchBlob(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        String creatorId = resolveCreatorId(partyId, partyType);

        List<RecoveryBlob> blobRows = dbClient.query(SELECT_ACTIVE_BLOB,
                RecoveryBlobRowMapper.INSTANCE, creatorId);
        if (blobRows.isEmpty()) {
            throw AppException.notFound("recovery_blob");
        }
        RecoveryBlob blob = blobRows.get(0);

        Integer myLayerOrder = null;
        String myKeyFingerprint = null;
        if (partyType != PartyType.CREATOR) {
            List<RecoveryBlobLayer> layerRows = dbClient.query(SELECT_MY_LAYER,
                    RecoveryBlobLayerRowMapper.INSTANCE, blob.blobId(), partyId,
                    partyType.name().toLowerCase());
            if (!layerRows.isEmpty()) {
                myLayerOrder = layerRows.get(0).layerOrder();
                myKeyFingerprint = layerRows.get(0).keyFingerprint();
            }
        }

        String encryptedBlobB64 = downloadFromS3OrDev(blob);

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.RECOVERY_BLOB_FETCHED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).targetId(blob.blobId())
                .build());

        log.info("Recovery blob fetched: partyId={} partyType={} blobId={}",
                partyId, partyType, blob.blobId());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new FetchBlobResponse(blob.blobId(), encryptedBlobB64, blob.layerCount(),
                        myLayerOrder, myKeyFingerprint),
                requestId));
    }

    private String resolveCreatorId(String partyId, PartyType partyType) {
        if (partyType == PartyType.CREATOR) {
            return partyId;
        }
        String sql;
        if (partyType == PartyType.NOMINEE) {
            sql = SELECT_CREATOR_ID_FOR_NOMINEE;
        } else if (partyType == PartyType.LAWYER) {
            sql = SELECT_CREATOR_ID_FOR_LAWYER;
        } else {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                    "Party type not authorized for recovery blob access");
        }
        List<String> rows = dbClient.query(sql, STRING_MAPPER, partyId);
        if (rows.isEmpty()) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Cannot resolve creator for this party");
        }
        return rows.get(0);
    }

    private String downloadFromS3OrDev(RecoveryBlob blob) {
        if (s3BucketName == null || s3BucketName.isBlank() || blob.s3Key() == null) {
            log.warn("[DEV] S3 download skipped for blobId={}", blob.blobId());
            return Base64.getEncoder().encodeToString("DEV_BLOB".getBytes());
        }
        byte[] bytes = s3Client.getObjectAsBytes(
                GetObjectRequest.builder().bucket(s3BucketName).key(blob.s3Key()).build()
        ).asByteArray();
        return Base64.getEncoder().encodeToString(bytes);
    }

    private record FetchBlobResponse(
            String blobId,
            String encryptedBlobB64,
            int layerCount,
            Integer myLayerOrder,
            String myKeyFingerprint
    ) {}
}
