package in.deathtrap.locker.routes.familyvault;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E011 Phase 1B — Family Vault closure flow endpoints.
 *  Mounted under /locker/family-vault/closure/* (Path A route prefix).
 *  Path B locked: server stores no .fvpack; export-manifest returns
 *  category + audit metadata only. FE assembles the package client-side. */
@RestController
@RequestMapping("/locker/family-vault/closure")
public class FamilyVaultClosureHandler {

    private static final Logger log = LoggerFactory.getLogger(FamilyVaultClosureHandler.class);

    private static final String SELECT_CREATOR_DISPLAY_NAME =
            "SELECT full_name FROM users WHERE user_id = ? LIMIT 1";

    // Most recent closure row for the creator (open or terminal).
    private static final String SELECT_CLOSURE_FOR_CREATOR =
            "SELECT closure_id, creator_id, trigger_kind::text AS trigger_kind, triggered_at, " +
            "objection_window_ends_at, status::text AS status, cancelled_at, " +
            "cancelled_by_party_id, cancelled_reason, finalised_at, archive_s3_prefix " +
            "FROM account_closure WHERE creator_id = ? ORDER BY triggered_at DESC LIMIT 1";

    // Nominee's wrap status for a specific closure's creator — for export manifest gating.
    private static final String SELECT_NOMINEE_WRAP_STATUS_FOR_CLOSURE =
            "SELECT fvw.status::text FROM family_vault_wraps fvw " +
            "JOIN account_closure ac ON ac.creator_id = fvw.creator_id " +
            "WHERE ac.closure_id = ? AND fvw.nominee_party_id = ? " +
            "ORDER BY fvw.created_at DESC LIMIT 1";

    // Closure row by ID.
    private static final String SELECT_CLOSURE_BY_ID =
            "SELECT closure_id, creator_id, trigger_kind::text AS trigger_kind, triggered_at, " +
            "objection_window_ends_at, status::text AS status, cancelled_at, " +
            "cancelled_by_party_id, cancelled_reason, finalised_at, archive_s3_prefix " +
            "FROM account_closure WHERE closure_id = ? LIMIT 1";

    private static final String UPDATE_CLOSURE_CANCELLED =
            "UPDATE account_closure SET status = 'cancelled', cancelled_at = NOW(), " +
            "cancelled_by_party_id = ?, cancelled_reason = ? " +
            "WHERE closure_id = ? AND status = 'pending_objection'";

    // Used to populate /status's myExport block + check whether the nominee has fetched yet.
    private static final String SELECT_EXPORT_ACK_FOR_NOMINEE =
            "SELECT ack_id, first_fetched_at, last_fetched_at, fetch_count " +
            "FROM closure_export_acknowledgement " +
            "WHERE closure_id = ? AND recipient_party_id = ? LIMIT 1";

    // Categories present in the archived locker — drives the export-manifest payload.
    private static final String SELECT_LOCKER_FOR_CREATOR =
            "SELECT locker_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_CATEGORIES_FOR_LOCKER =
            "SELECT bv.blob_id, ai.category_code, bv.size_bytes, bv.content_hash_sha256, " +
            "bv.version, bv.created_at " +
            "FROM blob_versions bv JOIN asset_index ai ON ai.asset_id = bv.asset_id " +
            "WHERE ai.locker_id = ? AND bv.is_current = TRUE " +
            "ORDER BY ai.category_code";

    // Insert/upsert the export-acknowledgement row.
    private static final String UPSERT_EXPORT_ACK =
            "INSERT INTO closure_export_acknowledgement " +
            "(ack_id, closure_id, recipient_party_id, first_fetched_at, last_fetched_at, fetch_count) " +
            "VALUES (?, ?, ?, NOW(), NOW(), 1) " +
            "ON CONFLICT (closure_id, recipient_party_id) DO UPDATE " +
            "SET last_fetched_at = NOW(), fetch_count = closure_export_acknowledgement.fetch_count + 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<ClosureRow> CLOSURE_ROW_MAPPER = (rs, row) -> new ClosureRow(
            rs.getString("closure_id"),
            rs.getString("creator_id"),
            rs.getString("trigger_kind"),
            rs.getTimestamp("triggered_at").toInstant(),
            rs.getTimestamp("objection_window_ends_at").toInstant(),
            rs.getString("status"),
            Optional.ofNullable(rs.getTimestamp("cancelled_at")).map(Timestamp::toInstant).orElse(null),
            rs.getString("cancelled_by_party_id"),
            rs.getString("cancelled_reason"),
            Optional.ofNullable(rs.getTimestamp("finalised_at")).map(Timestamp::toInstant).orElse(null),
            rs.getString("archive_s3_prefix"));
    private static final RowMapper<ExportAckRow> EXPORT_ACK_MAPPER = (rs, row) -> new ExportAckRow(
            rs.getString("ack_id"),
            rs.getTimestamp("first_fetched_at").toInstant(),
            rs.getTimestamp("last_fetched_at").toInstant(),
            rs.getInt("fetch_count"));
    private static final RowMapper<CategoryRow> CATEGORY_ROW_MAPPER = (rs, row) -> new CategoryRow(
            rs.getString("blob_id"),
            rs.getString("category_code"),
            rs.getLong("size_bytes"),
            rs.getString("content_hash_sha256"),
            rs.getInt("version"),
            rs.getTimestamp("created_at").toInstant());

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    public FamilyVaultClosureHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** GET /locker/family-vault/closure/status — creator or nominee. */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<ClosureStatusResponse>> getStatus(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateAnyJwt(authHeader);
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        String creatorId;
        if (partyType == PartyType.CREATOR) {
            creatorId = partyId;
        } else if (partyType == PartyType.NOMINEE) {
            // For nominees, find any creator they have a wrap relationship with that has an
            // active or recently-terminal closure. Returns null if no closure is open for any
            // of the nominee's creators (most common case).
            creatorId = findCreatorWithClosureForNominee(partyId);
        } else {
            throw AppException.forbidden();
        }

        if (creatorId == null) {
            return ResponseEntity.ok(ApiResponse.ok(new ClosureStatusResponse(null), UUID.randomUUID().toString()));
        }

        Optional<ClosureRow> closureOpt = dbClient.queryOne(SELECT_CLOSURE_FOR_CREATOR,
                CLOSURE_ROW_MAPPER, creatorId);
        if (closureOpt.isEmpty()) {
            return ResponseEntity.ok(ApiResponse.ok(new ClosureStatusResponse(null), UUID.randomUUID().toString()));
        }

        ClosureRow closure = closureOpt.get();
        String creatorDisplayName = dbClient.queryOne(SELECT_CREATOR_DISPLAY_NAME, STRING_MAPPER, creatorId)
                .orElse("");

        MyExportSummary myExport = null;
        if (partyType == PartyType.NOMINEE && ("finalising".equals(closure.status) || "closed".equals(closure.status))) {
            Optional<ExportAckRow> ackOpt = dbClient.queryOne(SELECT_EXPORT_ACK_FOR_NOMINEE,
                    EXPORT_ACK_MAPPER, closure.closureId, partyId);
            myExport = ackOpt.map(a -> new MyExportSummary(
                    "closed".equals(closure.status) ? "ready" : "queued",
                    a.firstFetchedAt, a.lastFetchedAt, a.fetchCount)).orElse(
                    new MyExportSummary(
                            "closed".equals(closure.status) ? "ready" : "queued",
                            null, null, 0));
        }

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_CLOSURE_STATUS_READ, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).targetId(closure.closureId)
                .metadataJson(Map.of(
                        "closureId", closure.closureId,
                        "creatorId", creatorId,
                        "closureStatus", closure.status))
                .build());

        ClosureSummary summary = new ClosureSummary(
                closure.closureId, creatorId, creatorDisplayName, closure.triggerKind,
                closure.triggeredAt, closure.objectionWindowEndsAt, closure.status,
                closure.cancelledAt, partyTypeOf(closure.cancelledByPartyId),
                closure.finalisedAt, closure.archiveS3Prefix != null, myExport);

        return ResponseEntity.ok(ApiResponse.ok(new ClosureStatusResponse(summary), UUID.randomUUID().toString()));
    }

    /** POST /locker/family-vault/closure/{closureId}/object — creator objects to closure. */
    @PostMapping("/{closureId}/object")
    public ResponseEntity<ApiResponse<ObjectResponse>> objectClosure(
            @PathVariable String closureId,
            @RequestBody(required = false) @Valid ObjectionRequest body,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String partyId = jwt.sub();

        ClosureRow closure = dbClient.queryOne(SELECT_CLOSURE_BY_ID, CLOSURE_ROW_MAPPER, closureId)
                .orElseThrow(() -> new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_NOT_FOUND,
                        "Closure not found: " + closureId));

        if (!partyId.equals(closure.creatorId)) {
            throw AppException.forbidden();
        }

        switch (closure.status) {
            case "pending_objection":
                // OK to object.
                break;
            case "cancelled":
            case "closed":
            case "finalising":
                throw new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_NOT_OBJECTABLE,
                        "Closure is in terminal state: " + closure.status);
            default:
                throw new AppException(ErrorCode.CONFLICT,
                        "Unknown closure status: " + closure.status);
        }

        // Worker may have already transitioned us mid-request — check expiry explicitly.
        if (!Instant.now().isBefore(closure.objectionWindowEndsAt)) {
            throw new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_WINDOW_EXPIRED,
                    "Objection window expired at " + closure.objectionWindowEndsAt);
        }

        String reason = body != null && body.reason() != null && !body.reason().isBlank()
                ? body.reason().trim()
                : null;

        int updated = dbClient.execute(UPDATE_CLOSURE_CANCELLED, partyId, reason, closureId);
        if (updated != 1) {
            // Lost a race — worker beat us.
            throw new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_WINDOW_EXPIRED,
                    "Closure transitioned away from pending_objection concurrently");
        }

        Instant cancelledAt = Instant.now();

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_CLOSURE_CANCELLED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(PartyType.CREATOR).targetId(closureId)
                .metadataJson(Map.of(
                        "closureId", closureId,
                        "creatorId", closure.creatorId,
                        "cancelledReason", reason != null ? reason : ""))
                .build());

        log.info("Family vault closure cancelled: closureId={} creatorId={} reason={}",
                closureId, closure.creatorId, reason);

        return ResponseEntity.ok(ApiResponse.ok(
                new ObjectResponse(closureId, "cancelled", cancelledAt, true),
                UUID.randomUUID().toString()));
    }

    /** GET /locker/family-vault/closure/{closureId}/export-manifest — Path B.
     *  Returns category listing + archive presence; no presigned URLs (FE builds the .fvpack
     *  client-side using existing GET /locker/blob/{cat} endpoints against the archived data). */
    @GetMapping("/{closureId}/export-manifest")
    public ResponseEntity<ApiResponse<ExportManifestResponse>> exportManifest(
            @PathVariable String closureId,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateNomineeJwt(authHeader);
        String nomineeId = jwt.sub();

        ClosureRow closure = dbClient.queryOne(SELECT_CLOSURE_BY_ID, CLOSURE_ROW_MAPPER, closureId)
                .orElseThrow(() -> new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_NOT_FOUND,
                        "Closure not found: " + closureId));

        // Caller must have (had) a wrap on this closure's creator.
        Optional<String> wrapStatusOpt = dbClient.queryOne(SELECT_NOMINEE_WRAP_STATUS_FOR_CLOSURE,
                STRING_MAPPER, closureId, nomineeId);
        if (wrapStatusOpt.isEmpty()) {
            throw AppException.forbidden();
        }

        // Closure must be in a state where the export is available.
        switch (closure.status) {
            case "pending_objection":
            case "cancelled":
                throw new AppException(ErrorCode.FAMILY_VAULT_EXPORT_NOT_READY,
                        "Closure status is " + closure.status + "; export not available");
            case "finalising":
                throw new AppException(ErrorCode.FAMILY_VAULT_EXPORT_NOT_READY,
                        "Archive in progress");
            case "closed":
                // OK.
                break;
            default:
                throw new AppException(ErrorCode.CONFLICT,
                        "Unknown closure status: " + closure.status);
        }

        // List archived categories. Even though the closure is closed, the row IDs still point
        // at the live blob_versions for now — the read path (DownloadBlobHandler) is what
        // routes to the archive bucket post-closure (Chunk B).
        String lockerId = dbClient.queryOne(SELECT_LOCKER_FOR_CREATOR, STRING_MAPPER, closure.creatorId)
                .orElseThrow(() -> AppException.notFound("locker"));
        List<CategoryRow> categories = dbClient.query(SELECT_CATEGORIES_FOR_LOCKER,
                CATEGORY_ROW_MAPPER, lockerId);

        // Acknowledge fetch — bumps count for ops + drives §9.4 7-day reminder logic.
        String ackId = CsprngUtil.randomUlid();
        dbClient.execute(UPSERT_EXPORT_ACK, ackId, closureId, nomineeId);

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_EXPORT_MANIFEST_FETCHED, AuditResult.SUCCESS)
                .actorId(nomineeId).actorType(PartyType.NOMINEE).targetId(closureId)
                .metadataJson(Map.of(
                        "closureId", closureId,
                        "creatorId", closure.creatorId,
                        "categoryCount", categories.size()))
                .build());

        List<ExportCategory> exportCategories = categories.stream()
                .map(c -> new ExportCategory(
                        c.categoryCode, c.blobId, c.sizeBytes,
                        c.contentHashSha256, c.version, c.uploadedAt))
                .toList();

        ExportManifestResponse resp = new ExportManifestResponse(
                closureId, closure.creatorId, closure.finalisedAt,
                closure.archiveS3Prefix != null, exportCategories);

        return ResponseEntity.ok(ApiResponse.ok(resp, UUID.randomUUID().toString()));
    }

    private String findCreatorWithClosureForNominee(String nomineeId) {
        Optional<String> creatorIdOpt = dbClient.queryOne(
                "SELECT ac.creator_id FROM account_closure ac " +
                "JOIN family_vault_wraps fvw ON fvw.creator_id = ac.creator_id " +
                "WHERE fvw.nominee_party_id = ? " +
                "AND ac.status IN ('pending_objection','finalising','closed') " +
                "ORDER BY ac.triggered_at DESC LIMIT 1",
                STRING_MAPPER, nomineeId);
        return creatorIdOpt.orElse(null);
    }

    private String partyTypeOf(String partyId) {
        if (partyId == null) return null;
        // Heuristic: if it's the creator's own row, the cancellation came from CREATOR.
        // For SYSTEM-driven transitions, cancelled_by_party_id stays null. We don't try to
        // distinguish CREATOR vs NOMINEE objections at the column level since the closure flow
        // is creator-only objection per §4.2.
        return "CREATOR";
    }

    private JwtPayload validateAnyJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR && jwt.partyType() != PartyType.NOMINEE) {
            throw AppException.forbidden();
        }
        return jwt;
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

    private JwtPayload validateNomineeJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.NOMINEE) {
            throw AppException.forbidden();
        }
        return jwt;
    }

    public record ObjectionRequest(String reason) {}

    private record ClosureRow(
            String closureId,
            String creatorId,
            String triggerKind,
            Instant triggeredAt,
            Instant objectionWindowEndsAt,
            String status,
            Instant cancelledAt,
            String cancelledByPartyId,
            String cancelledReason,
            Instant finalisedAt,
            String archiveS3Prefix
    ) {}

    private record ExportAckRow(String ackId, Instant firstFetchedAt, Instant lastFetchedAt, int fetchCount) {}

    private record CategoryRow(String blobId, String categoryCode, long sizeBytes,
            String contentHashSha256, int version, Instant uploadedAt) {}

    // ────────────────────────────────────────────────────────────────────
    // Response shapes
    // ────────────────────────────────────────────────────────────────────

    private record ClosureStatusResponse(ClosureSummary closure) {}

    private record ClosureSummary(
            String closureId,
            String creatorId,
            String creatorDisplayName,
            String triggerKind,
            Instant triggeredAt,
            Instant objectionWindowEndsAt,
            String status,
            Instant cancelledAt,
            String cancelledByPartyType,
            Instant finalisedAt,
            boolean archivePresent,
            MyExportSummary myExport
    ) {}

    private record MyExportSummary(
            String status,
            Instant firstFetchedAt,
            Instant lastFetchedAt,
            int fetchCount
    ) {}

    private record ObjectResponse(
            String closureId,
            String newStatus,
            Instant cancelledAt,
            boolean writeGateLifted
    ) {}

    private record ExportManifestResponse(
            String closureId,
            String creatorId,
            Instant finalisedAt,
            boolean archivePresent,
            List<ExportCategory> categories
    ) {}

    private record ExportCategory(
            String categoryCode,
            String blobVersionId,
            long sizeBytes,
            String contentHashSha256,
            int version,
            Instant uploadedAt
    ) {}
}
