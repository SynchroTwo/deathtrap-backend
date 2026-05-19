package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.BlobLayerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.StoreBlobRequest;
import in.deathtrap.common.types.dto.StoreBlobResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.service.BlobRebuildLogService;
import in.deathtrap.recovery.service.RecoveryBlobRateLimit;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
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

/** Handles storing a layered recovery blob from the creator.
 *  Implements Recovery Blob Format v1 per docs/RECOVERY_BLOB_FORMAT.md and
 *  docs/RECOVERY_SPEC_V1_BACKEND_CHANGES.md (rev 2). */
@RestController
@RequestMapping("/recovery/blob")
public class StoreBlobHandler {

    private static final Logger log = LoggerFactory.getLogger(StoreBlobHandler.class);
    private static final List<String> SUPPORTED_SPEC_VERSIONS = List.of("v1");
    private static final int MIN_LAYERS = 2;
    private static final int MAX_LAYERS = 7;
    private static final int MAX_BLOB_B64_BYTES = 32 * 1024;
    private static final Set<String> ALLOWED_REBUILD_REASONS = Set.of(
            "initial", "nominee_added", "nominee_removed",
            "lawyer_changed", "key_rotated", "other");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern PEM_HEADERS = Pattern.compile(
            "-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+");

    private static final String SELECT_NOMINEE_OWNED =
            "SELECT 1 FROM nominees WHERE nominee_id = ? AND creator_id = ? " +
            "AND status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_LAWYER_ACTIVE =
            "SELECT 1 FROM lawyers WHERE lawyer_id = ? " +
            "AND status = 'active'::lawyer_status_enum AND kyc_admin_approved = TRUE LIMIT 1";
    private static final String SELECT_ACTIVE_PUBKEY =
            "SELECT pubkey_id, public_key_pem FROM party_public_keys " +
            "WHERE party_id = ? AND party_type = ?::party_type_enum AND is_active = TRUE LIMIT 1";
    private static final String SELECT_ACTIVE_BLOB =
            "SELECT blob_id FROM recovery_blobs WHERE creator_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_BLOB_BY_ID =
            "SELECT blob_id FROM recovery_blobs WHERE blob_id = ? LIMIT 1";
    private static final String SELECT_CREATOR_BLOB_COUNT =
            "SELECT COUNT(*) FROM recovery_blobs WHERE creator_id = ?";
    private static final String SUPERSEDE_BLOB =
            "UPDATE recovery_blobs SET status = 'superseded', updated_at = NOW() " +
            "WHERE creator_id = ? AND status = 'active'";
    private static final String INSERT_BLOB =
            "INSERT INTO recovery_blobs (blob_id, creator_id, s3_key, layer_count, status, " +
            "spec_version, built_at, created_at) VALUES (?, ?, ?, ?, 'active', ?, NOW(), NOW())";
    private static final String INSERT_LAYER =
            "INSERT INTO recovery_blob_layers (layer_id, blob_id, layer_order, party_id, " +
            "party_type, pubkey_id, key_fingerprint, spec_version, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())";
    private static final String UPDATE_LOCKER_BLOB_BUILT =
            "UPDATE locker_meta SET blob_built = TRUE, updated_at = NOW() WHERE user_id = ?";

    private static final RowMapper<Integer> ONE_MAPPER = (rs, row) -> 1;
    private static final RowMapper<PubkeyRow> PUBKEY_MAPPER = (rs, row) ->
            new PubkeyRow(rs.getString("pubkey_id"), rs.getString("public_key_pem"));
    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Client s3Client;
    private final BlobRebuildLogService rebuildLogService;
    private final RecoveryBlobRateLimit rateLimit;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    @Value("${KMS_KEY_ID:}")
    private String kmsKeyId;

    /** Constructs StoreBlobHandler with required dependencies. */
    public StoreBlobHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter,
            S3Client s3Client, BlobRebuildLogService rebuildLogService,
            RecoveryBlobRateLimit rateLimit) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Client = s3Client;
        this.rebuildLogService = rebuildLogService;
        this.rateLimit = rateLimit;
    }

    /** POST /recovery/blob — validates v1 wire format, uploads to S3, records DB rows atomically. */
    @PostMapping
    public ResponseEntity<ApiResponse<StoreBlobResponse>> storeBlob(
            @RequestBody @Valid StoreBlobRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        // Rule 1: spec version known
        if (!SUPPORTED_SPEC_VERSIONS.contains(request.specVersion())) {
            throw AppException.recoveryUnsupportedSpecVersion(
                    request.specVersion(), SUPPORTED_SPEC_VERSIONS);
        }

        // blobId format check (UUID v4 lowercase canonical)
        if (!UUID_PATTERN.matcher(request.blobId()).matches()) {
            throw AppException.validationFailed(Map.of("blobId",
                    "Must be lowercase UUID v4 canonical form (8-4-4-4-12 hex)"));
        }

        // Rule 9: rebuildReason enum
        if (!ALLOWED_REBUILD_REASONS.contains(request.rebuildReason())) {
            throw AppException.validationFailed(Map.of(
                    "field", "rebuildReason",
                    "allowed", ALLOWED_REBUILD_REASONS));
        }

        List<BlobLayerRequest> layers = request.layers();

        // Rule 3: layer count bounds
        if (layers.size() < MIN_LAYERS || layers.size() > MAX_LAYERS) {
            throw AppException.recoveryLayerCountOutOfBounds(layers.size());
        }

        // Rule 8: encrypted blob size cap (on the base64 string itself — cheap pre-decode guard)
        if (request.encryptedBlobB64().length() > MAX_BLOB_B64_BYTES) {
            throw AppException.recoveryBlobTooLarge(request.encryptedBlobB64().length(), MAX_BLOB_B64_BYTES);
        }

        // Rule 10: rate limit (DB count of recent uploads)
        rateLimit.check(creatorId);

        // Rule 7: layerOrder dense 1..N
        validateLayerOrdering(layers);

        // Rule 2: lawyer at order=1, nominees thereafter
        validateRecipientOrder(layers);

        // Rule 6: no duplicate recipients
        validateNoDuplicates(layers);

        // Rules 4 + 5: existence + fingerprint match per layer
        List<String> resolvedPubkeyIds = new java.util.ArrayList<>(layers.size());
        for (BlobLayerRequest layer : layers) {
            validateRecipientExistence(layer, creatorId);
            String pubkeyId = resolveAndVerifyPubkey(layer);
            resolvedPubkeyIds.add(pubkeyId);
        }

        // Conflict check: client-supplied blobId must not collide with an existing row
        // (extremely unlikely with UUID v4, but cheap to catch and gives a clear error).
        if (dbClient.queryOne(SELECT_BLOB_BY_ID, STRING_MAPPER, request.blobId()).isPresent()) {
            throw AppException.conflict("blob_id collision (client-generated UUID v4 already exists)");
        }

        List<String> oldBlobRows = dbClient.query(SELECT_ACTIVE_BLOB, STRING_MAPPER, creatorId);
        String oldBlobId = oldBlobRows.isEmpty() ? null : oldBlobRows.get(0);

        String blobId = request.blobId();
        String s3Key = "recovery/" + creatorId + "/" + blobId;
        putToS3OrDev(blobId, s3Key, request.encryptedBlobB64());

        int blobCount = dbClient.queryOne(SELECT_CREATOR_BLOB_COUNT, INT_MAPPER, creatorId).orElse(0);
        int newVersion = blobCount + 1;

        dbClient.withTransaction(status -> {
            if (oldBlobId != null) {
                dbClient.execute(SUPERSEDE_BLOB, creatorId);
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.RECOVERY_BLOB_SUPERSEDED, AuditResult.SUCCESS)
                        .actorId(creatorId).actorType(PartyType.CREATOR).targetId(oldBlobId)
                        .build());
            }
            dbClient.execute(INSERT_BLOB, blobId, creatorId, s3Key, layers.size(), request.specVersion());
            for (int i = 0; i < layers.size(); i++) {
                BlobLayerRequest layer = layers.get(i);
                String layerId = CsprngUtil.randomUlid();
                dbClient.execute(INSERT_LAYER,
                        layerId, blobId, layer.layerOrder(),
                        layer.partyId(), layer.partyType(),
                        resolvedPubkeyIds.get(i),
                        layer.keyFingerprint(),
                        request.specVersion());
            }
            dbClient.execute(UPDATE_LOCKER_BLOB_BUILT, creatorId);
            return null;
        });

        rebuildLogService.log(creatorId, oldBlobId, blobId, request.rebuildReason(),
                creatorId, "creator");

        Instant uploadedAt = Instant.now();
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.RECOVERY_BLOB_STORED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(blobId)
                .metadataJson(Map.of(
                        "specVersion", request.specVersion(),
                        "layerCount", layers.size(),
                        "version", newVersion,
                        "rebuildReason", request.rebuildReason()))
                .build());

        log.info("Recovery blob stored: creatorId={} blobId={} layers={} version={} spec={}",
                creatorId, blobId, layers.size(), newVersion, request.specVersion());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new StoreBlobResponse(blobId, newVersion, uploadedAt), requestId));
    }

    private void validateLayerOrdering(List<BlobLayerRequest> layers) {
        Set<Integer> seen = new HashSet<>();
        for (BlobLayerRequest layer : layers) {
            if (!seen.add(layer.layerOrder())) {
                throw AppException.recoveryInvalidLayerOrdering(
                        "Duplicate layerOrder: " + layer.layerOrder());
            }
            if (layer.layerOrder() < 1 || layer.layerOrder() > layers.size()) {
                throw AppException.recoveryInvalidLayerOrdering(
                        "layerOrder " + layer.layerOrder() + " out of range [1.." + layers.size() + "]");
            }
        }
    }

    private void validateRecipientOrder(List<BlobLayerRequest> layers) {
        BlobLayerRequest first = findByLayerOrder(layers, 1);
        if (!"lawyer".equals(first.partyType())) {
            throw AppException.recoveryInvalidRecipientOrder(
                    "layerOrder=1 must be lawyer, got " + first.partyType());
        }
        for (BlobLayerRequest layer : layers) {
            if (layer.layerOrder() == 1) {
                continue;
            }
            if (!"nominee".equals(layer.partyType())) {
                throw AppException.recoveryInvalidRecipientOrder(
                        "layerOrder=" + layer.layerOrder() + " must be nominee, got " + layer.partyType());
            }
        }
    }

    private void validateNoDuplicates(List<BlobLayerRequest> layers) {
        Set<String> seen = new LinkedHashSet<>();
        for (BlobLayerRequest layer : layers) {
            if (!seen.add(layer.partyId())) {
                throw AppException.recoveryDuplicateRecipient(layer.partyId());
            }
        }
    }

    private void validateRecipientExistence(BlobLayerRequest layer, String creatorId) {
        if ("nominee".equals(layer.partyType())) {
            if (dbClient.queryOne(SELECT_NOMINEE_OWNED, ONE_MAPPER, layer.partyId(), creatorId).isEmpty()) {
                throw AppException.recoveryUnknownRecipient(layer.partyId(), layer.partyType());
            }
        } else if ("lawyer".equals(layer.partyType())) {
            if (dbClient.queryOne(SELECT_LAWYER_ACTIVE, ONE_MAPPER, layer.partyId()).isEmpty()) {
                throw AppException.recoveryUnknownRecipient(layer.partyId(), layer.partyType());
            }
            // Note: there is no creator->lawyer assignment table today. Any active,
            // KYC-approved lawyer is acceptable as a recovery blob recipient. If
            // product later adds a creator_lawyer_assignments table, tighten this
            // to require an assignment row.
        } else {
            throw AppException.recoveryInvalidRecipientOrder(
                    "Unknown partyType: " + layer.partyType());
        }
    }

    /** Returns the active pubkey_id for this recipient, after verifying its SHA-256(SPKI DER)
     *  matches the client-supplied keyFingerprint. Throws RECOVERY_STALE_RECIPIENT_KEY on mismatch
     *  or RECOVERY_UNKNOWN_RECIPIENT if no active pubkey is registered. */
    private String resolveAndVerifyPubkey(BlobLayerRequest layer) {
        PubkeyRow row = dbClient.queryOne(SELECT_ACTIVE_PUBKEY, PUBKEY_MAPPER,
                layer.partyId(), layer.partyType())
                .orElseThrow(() -> AppException.recoveryUnknownRecipient(
                        layer.partyId(), layer.partyType()));
        String currentFingerprint = fingerprintFromPem(row.publicKeyPem());
        if (!currentFingerprint.equalsIgnoreCase(layer.keyFingerprint())) {
            throw AppException.recoveryStaleRecipientKey(
                    layer.partyId(), layer.partyType(),
                    currentFingerprint, layer.keyFingerprint());
        }
        return row.pubkeyId();
    }

    /** Strips PEM armor/whitespace, base64-decodes the SPKI DER, returns lowercase hex SHA-256. */
    private static String fingerprintFromPem(String pem) {
        String b64 = PEM_HEADERS.matcher(pem).replaceAll("");
        byte[] der = Base64.getDecoder().decode(b64);
        return Sha256Util.hashHex(der);
    }

    private static BlobLayerRequest findByLayerOrder(List<BlobLayerRequest> layers, int order) {
        for (BlobLayerRequest layer : layers) {
            if (layer.layerOrder() == order) {
                return layer;
            }
        }
        throw AppException.recoveryInvalidLayerOrdering("Missing layerOrder=" + order);
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

    record PubkeyRow(String pubkeyId, String publicKeyPem) {}
}
