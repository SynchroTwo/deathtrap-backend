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
import java.util.Optional;
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
import org.springframework.web.bind.annotation.RequestParam;
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
    // E011 Path Y: nominee fetches via an active family_vault_wraps row for the named creator.
    private static final String SELECT_LOCKER_FOR_FAMILY_VAULT =
            "SELECT lm.locker_id, fvw.wrap_id FROM family_vault_wraps fvw " +
            "JOIN locker_meta lm ON lm.user_id = fvw.creator_id " +
            "WHERE fvw.nominee_party_id = ? AND fvw.creator_id = ? AND fvw.status = 'active' LIMIT 1";
    // E006 fallback for nominees — restricted to the named creator (no more LIMIT 1 fuzziness).
    private static final String SELECT_LOCKER_FOR_NOMINEE_BY_CREATOR =
            "SELECT lm.locker_id FROM locker_meta lm " +
            "JOIN nominees n ON n.creator_id = lm.user_id " +
            "WHERE n.nominee_id = ? AND lm.user_id = ? " +
            "AND n.status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_REVOKED_WRAP_EXISTS =
            "SELECT 1 FROM family_vault_wraps WHERE nominee_party_id = ? AND creator_id = ? AND status = 'revoked' LIMIT 1";
    // E011 Phase 1C §10.1 — always-on access log on nominee Family Vault reads.
    // The toggle (locker_meta.notify_on_nominee_access) gates fan-out only;
    // the log itself runs regardless so the §10.4 recent-access summary stays
    // accurate even when the creator hasn't opted in to notifications.
    private static final String UPSERT_ACCESS_LOG =
            "INSERT INTO creator_access_notification_log " +
            "(creator_id, nominee_party_id, pending_count, first_pending_at, last_access_at) " +
            "VALUES (?, ?, 1, NOW(), NOW()) " +
            "ON CONFLICT (creator_id, nominee_party_id) DO UPDATE " +
            "SET pending_count = creator_access_notification_log.pending_count + 1, " +
            "    first_pending_at = COALESCE(creator_access_notification_log.first_pending_at, NOW()), " +
            "    last_access_at = NOW()";

    // E011 Phase 1C §7.2 — post-finalise read-path branch. When the closure is closed,
    // the archive copy is complete, and the 7d live-bucket grace has elapsed, reads
    // are served from the archive prefix instead. Prior to the 7d grace, the live
    // ciphertext is still authoritative (S3 lifecycle hasn't expired it yet).
    private static final String SELECT_ARCHIVE_FOR_CREATOR =
            "SELECT archive_bucket, archive_s3_prefix FROM account_closure " +
            "WHERE creator_id = ? AND status = 'closed' " +
            "AND archive_complete_at IS NOT NULL " +
            "AND finalised_at <= NOW() - INTERVAL '7 days' " +
            "LIMIT 1";
    private static final String SELECT_CREATOR_FOR_LOCKER =
            "SELECT user_id FROM locker_meta WHERE locker_id = ? LIMIT 1";
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
    private static final RowMapper<ArchiveLocation> ARCHIVE_MAPPER = (rs, row) ->
            new ArchiveLocation(rs.getString("archive_bucket"), rs.getString("archive_s3_prefix"));

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

    /** GET /locker/blob/{categoryCode} — resolves locker, generates presigned S3 URL.
     *  Nominee callers must pass ?creatorId=&lt;id&gt; identifying which shared
     *  locker to access (E011 Path Y multi-creator disambiguation). Creators
     *  and lawyers don't need the param. */
    @GetMapping("/{categoryCode}")
    public ResponseEntity<ApiResponse<DownloadBlobResponse>> downloadBlob(
            @PathVariable String categoryCode,
            @RequestParam(value = "creatorId", required = false) String creatorIdParam,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        LockerResolution resolution = resolveLockerId(partyId, partyType, creatorIdParam);
        String lockerId = resolution.lockerId();

        List<BlobVersion> blobRows = dbClient.query(SELECT_BLOB, BlobVersionRowMapper.INSTANCE, lockerId, categoryCode);
        if (blobRows.isEmpty()) {
            throw AppException.notFound("blob");
        }
        BlobVersion blob = blobRows.get(0);

        String downloadUrl = buildPresignedUrl(blob);

        // §10.1 — log Family Vault nominee accesses always (toggle gates fan-out only).
        if (partyType == PartyType.NOMINEE && resolution.viaWrapId() != null) {
            String creatorForLog = dbClient.queryOne(SELECT_CREATOR_FOR_LOCKER, STRING_MAPPER, lockerId)
                    .orElse(null);
            if (creatorForLog != null) {
                try {
                    dbClient.execute(UPSERT_ACCESS_LOG, creatorForLog, partyId);
                } catch (Exception ex) {
                    log.warn("Access-log upsert failed: creatorId={} nomineeId={} err={}",
                            creatorForLog, partyId, ex.getMessage());
                }
            }
        }

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

    private LockerResolution resolveLockerId(String partyId, PartyType partyType, String creatorIdParam) {
        if (partyType == PartyType.CREATOR) {
            List<String> rows = dbClient.query(SELECT_LOCKER_FOR_CREATOR, STRING_MAPPER, partyId);
            if (rows.isEmpty()) throw AppException.forbidden();
            return new LockerResolution(rows.get(0), null);
        }
        if (partyType == PartyType.NOMINEE) {
            if (creatorIdParam == null || creatorIdParam.isBlank()) {
                throw AppException.validationFailed(Map.of(
                        "field", "creatorId",
                        "message", "Nominee callers must specify ?creatorId=<id> identifying which shared locker to access"));
            }
            // E011 Path Y: prefer Family Vault wrap if active for (this nominee, this creator).
            List<FvLockerRow> fvRows = dbClient.query(SELECT_LOCKER_FOR_FAMILY_VAULT,
                    FV_LOCKER_MAPPER, partyId, creatorIdParam);
            if (!fvRows.isEmpty()) {
                return new LockerResolution(fvRows.get(0).lockerId(), fvRows.get(0).wrapId());
            }
            // E006 fallback for nominees — link to the named creator only.
            List<String> rows = dbClient.query(SELECT_LOCKER_FOR_NOMINEE_BY_CREATOR,
                    STRING_MAPPER, partyId, creatorIdParam);
            if (!rows.isEmpty()) return new LockerResolution(rows.get(0), null);
            // No access path — if the nominee USED to have a wrap for this creator,
            // emit the distinctive code so the FE can show "your access was revoked".
            if (dbClient.queryOne(SELECT_REVOKED_WRAP_EXISTS, ONE_MAPPER, partyId, creatorIdParam).isPresent()) {
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
        // §7.2 — if the blob's locker has an archived closure past the 7d live grace,
        // serve from the archive prefix (Glacier IR — millisecond restore). Otherwise
        // live bucket. The lookup is single-query, indexed, fires on every download —
        // expected cardinality is 1 row per creator that ever closed (vanishingly low
        // hit rate), so the cost is dominated by the S3 presign call either way.
        String bucket = s3BucketName;
        String key = blob.s3Key();
        String creatorId = dbClient.queryOne(SELECT_CREATOR_FOR_LOCKER, STRING_MAPPER, blob.lockerId())
                .orElse(null);
        if (creatorId != null) {
            Optional<ArchiveLocation> archive = dbClient.queryOne(SELECT_ARCHIVE_FOR_CREATOR,
                    ARCHIVE_MAPPER, creatorId);
            if (archive.isPresent() && archive.get().bucket() != null
                    && archive.get().prefix() != null) {
                bucket = archive.get().bucket();
                key = archive.get().prefix() + blob.s3Key();
            }
        }
        final String finalBucket = bucket;
        final String finalKey = key;
        PresignedGetObjectRequest presigned = s3Presigner.presignGetObject(r -> r
                .signatureDuration(Duration.ofSeconds(PRESIGNED_URL_SECONDS))
                .getObjectRequest(gor -> gor.bucket(finalBucket).key(finalKey)));
        return presigned.url().toString();
    }

    private record ArchiveLocation(String bucket, String prefix) {}

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
