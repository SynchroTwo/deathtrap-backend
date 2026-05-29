package in.deathtrap.locker.routes.blob;

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
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.BlobVersionRowMapper;
import in.deathtrap.locker.rowmapper.BlobVersionRowMapper.BlobVersion;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;

/** Handles encrypted blob downloads via presigned S3 URLs. */
@RestController
@RequestMapping("/locker/blob")
public class DownloadBlobHandler {

    private static final Logger log = LoggerFactory.getLogger(DownloadBlobHandler.class);
    private static final int PRESIGNED_URL_SECONDS = 300;

    private static final String SELECT_LOCKER_FOR_CREATOR =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_LOCKER_FOR_NOMINEE =
            "SELECT lm.locker_id FROM locker_meta lm " +
            "JOIN nominees n ON n.creator_id = lm.user_id " +
            "WHERE n.nominee_id = ? AND n.status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_LOCKER_FOR_LAWYER =
            "SELECT DISTINCT lm.locker_id FROM locker_meta lm " +
            "JOIN recovery_blob_layers rbl ON rbl.party_id = ? " +
            "JOIN recovery_blobs rb ON rbl.blob_id = rb.blob_id " +
            "WHERE rb.creator_id = lm.user_id AND rbl.party_type = 'lawyer'::party_type_enum " +
            "AND rb.status = 'active'::recovery_blob_status_enum LIMIT 1";
    // E011 Path Y: nominee fetches via an active family_vault_wraps row.
    private static final String SELECT_LOCKER_FOR_FAMILY_VAULT =
            "SELECT lm.locker_id, fvw.wrap_id FROM family_vault_wraps fvw " +
            "JOIN locker_meta lm ON lm.user_id = fvw.creator_id " +
            "WHERE fvw.nominee_party_id = ? AND fvw.status = 'active' " +
            "ORDER BY fvw.created_at DESC LIMIT 1";
    private static final String SELECT_REVOKED_WRAP_EXISTS =
            "SELECT 1 FROM family_vault_wraps WHERE nominee_party_id = ? AND status = 'revoked' LIMIT 1";
    private static final String SELECT_BLOB =
            "SELECT bv.blob_id, bv.asset_id, bv.locker_id, bv.s3_key, bv.size_bytes, " +
            "bv.content_hash_sha256, bv.schema_version, bv.version, bv.is_current, bv.created_at, bv.updated_at " +
            "FROM blob_versions bv " +
            "JOIN asset_index ai ON bv.asset_id = ai.asset_id " +
            "WHERE ai.locker_id = ? AND ai.category_code = ? AND bv.is_current = TRUE LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> ONE_MAPPER = (rs, row) -> 1;
    private static final RowMapper<FvLockerRow> FV_LOCKER_MAPPER = (rs, row) ->
            new FvLockerRow(rs.getString("locker_id"), rs.getString("wrap_id"));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Presigner s3Presigner;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    /** Constructs DownloadBlobHandler with required dependencies. */
    public DownloadBlobHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, S3Presigner s3Presigner) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Presigner = s3Presigner;
    }

    /** GET /locker/blob/{categoryCode} — resolves locker, generates presigned S3 URL. */
    @GetMapping("/{categoryCode}")
    public ResponseEntity<ApiResponse<DownloadBlobResponse>> downloadBlob(
            @PathVariable String categoryCode,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        LockerResolution resolution = resolveLockerId(partyId, partyType);
        String lockerId = resolution.lockerId();

        List<BlobVersion> blobRows = dbClient.query(SELECT_BLOB, BlobVersionRowMapper.INSTANCE, lockerId, categoryCode);
        if (blobRows.isEmpty()) {
            throw AppException.notFound("blob");
        }
        BlobVersion blob = blobRows.get(0);

        String downloadUrl = buildPresignedUrl(blob);

        AuditWritePayload.Builder auditBuilder = AuditWritePayload
                .builder(AuditEventType.BLOB_ACCESSED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).targetId(blob.assetId());
        if (resolution.viaWrapId() != null) {
            auditBuilder.metadataJson(Map.of(
                    "actorPartyType", partyType.name(),
                    "viaWrapId", resolution.viaWrapId()));
        } else {
            auditBuilder.metadataJson(Map.of("actorPartyType", partyType.name()));
        }
        auditWriter.write(auditBuilder.build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new DownloadBlobResponse(
                        blob.blobId(),
                        categoryCode,
                        downloadUrl,
                        PRESIGNED_URL_SECONDS,
                        blob.contentHashSha256(),
                        blob.sizeBytes(),
                        blob.version(),
                        blob.createdAt()),
                requestId));
    }

    private LockerResolution resolveLockerId(String partyId, PartyType partyType) {
        if (partyType == PartyType.CREATOR) {
            List<String> rows = dbClient.query(SELECT_LOCKER_FOR_CREATOR, STRING_MAPPER, partyId);
            if (rows.isEmpty()) throw AppException.forbidden();
            return new LockerResolution(rows.get(0), null);
        }
        if (partyType == PartyType.NOMINEE) {
            // E011 Path Y: prefer Family Vault wrap if active.
            List<FvLockerRow> fvRows = dbClient.query(SELECT_LOCKER_FOR_FAMILY_VAULT, FV_LOCKER_MAPPER, partyId);
            if (!fvRows.isEmpty()) {
                return new LockerResolution(fvRows.get(0).lockerId(), fvRows.get(0).wrapId());
            }
            // Else fall back to existing E006-style nominee resolution.
            List<String> rows = dbClient.query(SELECT_LOCKER_FOR_NOMINEE, STRING_MAPPER, partyId);
            if (!rows.isEmpty()) return new LockerResolution(rows.get(0), null);
            // No access path resolved — if the nominee USED to have a wrap, emit
            // the distinctive code so the FE can show a "your access was revoked"
            // landing instead of generic forbidden.
            if (dbClient.queryOne(SELECT_REVOKED_WRAP_EXISTS, ONE_MAPPER, partyId).isPresent()) {
                throw new AppException(ErrorCode.FAMILY_VAULT_WRAP_REVOKED,
                        "Your Family Vault access has been revoked");
            }
            throw AppException.forbidden();
        }
        if (partyType == PartyType.LAWYER) {
            List<String> rows = dbClient.query(SELECT_LOCKER_FOR_LAWYER, STRING_MAPPER, partyId);
            if (rows.isEmpty()) throw AppException.forbidden();
            return new LockerResolution(rows.get(0), null);
        }
        throw AppException.forbidden();
    }

    private record LockerResolution(String lockerId, String viaWrapId) {}

    private record FvLockerRow(String lockerId, String wrapId) {}

    private String buildPresignedUrl(BlobVersion blob) {
        if (s3BucketName == null || s3BucketName.isBlank() || blob.s3Key() == null) {
            log.warn("[DEV] Presigned URL generated locally for blobId={}", blob.blobId());
            return "http://localhost/dev-blob/" + blob.blobId();
        }
        String bucket = s3BucketName;
        String key = blob.s3Key();
        PresignedGetObjectRequest presigned = s3Presigner.presignGetObject(r -> r
                .signatureDuration(Duration.ofSeconds(PRESIGNED_URL_SECONDS))
                .getObjectRequest(gor -> gor.bucket(bucket).key(key)));
        return presigned.url().toString();
    }

    private record DownloadBlobResponse(
            String blobVersionId,
            String categoryCode,
            String downloadUrl,
            int expiresInSeconds,
            String contentHashSha256,
            Long sizeBytes,
            int version,
            Instant uploadedAt
    ) {}
}
