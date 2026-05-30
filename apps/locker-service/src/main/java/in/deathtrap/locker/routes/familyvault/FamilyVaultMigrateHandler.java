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
import in.deathtrap.locker.service.ClosureWriteGate;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E011 Phase 1C §11 — atomic recovery-mode migration between model_a, model_b,
 *  and family_vault. Pre-flight: ClosureWriteGate blocks the call with 423
 *  FAMILY_VAULT_CLOSURE_LOCKED when an open/finalising/closed closure exists
 *  (the migration mutates the same locker state). Each direction is one
 *  transaction with destructive side-effects:
 *    A/B → FV: requires at least one active wrap; supersedes the current
 *              recovery_blobs row.
 *    FV → A/B: requires a current recovery blob id; revokes every active wrap.
 *    A ↔ B:   no wrap/blob ops, just the mode flip. */
@RestController
@RequestMapping("/locker/family-vault/migrate")
public class FamilyVaultMigrateHandler {

    private static final Logger log = LoggerFactory.getLogger(FamilyVaultMigrateHandler.class);
    private static final Set<String> VALID_MODES = Set.of("model_a", "model_b", "family_vault");

    private static final String SELECT_CURRENT_MODE =
            "SELECT recovery_mode::text FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String UPDATE_RECOVERY_MODE =
            "UPDATE locker_meta SET recovery_mode = ?::recovery_mode_enum, updated_at = NOW() " +
            "WHERE user_id = ?";
    private static final String SELECT_ACTIVE_WRAP_COUNT =
            "SELECT COUNT(*) FROM family_vault_wraps WHERE creator_id = ? AND status = 'active'";
    private static final String SELECT_CURRENT_BLOB_EXISTS =
            "SELECT 1 FROM recovery_blobs WHERE creator_id = ? " +
            "AND blob_id = ? AND status = 'active'::recovery_blob_status_enum LIMIT 1";
    private static final String REVOKE_ALL_ACTIVE_WRAPS =
            "UPDATE family_vault_wraps SET status = 'revoked', revoked_at = NOW(), " +
            "revoked_reason = 'mode_migration' " +
            "WHERE creator_id = ? AND status = 'active'";
    private static final String SUPERSEDE_CURRENT_BLOB =
            "UPDATE recovery_blobs SET status = 'superseded'::recovery_blob_status_enum, " +
            "updated_at = NOW() " +
            "WHERE creator_id = ? AND status = 'active'::recovery_blob_status_enum";

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final ClosureWriteGate closureWriteGate;

    public FamilyVaultMigrateHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, ClosureWriteGate closureWriteGate) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.closureWriteGate = closureWriteGate;
    }

    /** POST /locker/family-vault/migrate — see contract §11.2. */
    @PostMapping
    public ResponseEntity<ApiResponse<MigrateResponse>> migrate(
            @RequestBody @Valid MigrateRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        // §14.5 LOCKED — block mode migration during pending/finalising/closed closure.
        closureWriteGate.assertWritesAllowed(creatorId);

        if (!VALID_MODES.contains(request.fromMode()) || !VALID_MODES.contains(request.toMode())) {
            throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_INVALID_TRANSITION,
                    "Modes must be one of model_a / model_b / family_vault");
        }
        if (request.fromMode().equals(request.toMode())) {
            throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_INVALID_TRANSITION,
                    "fromMode and toMode must differ");
        }

        String currentMode = dbClient.queryOne(SELECT_CURRENT_MODE, (rs, row) -> rs.getString(1), creatorId)
                .orElseThrow(() -> AppException.notFound("locker"));
        if (!currentMode.equals(request.fromMode())) {
            throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_INVALID_TRANSITION,
                    "Current mode is " + currentMode + ", not " + request.fromMode());
        }

        // Pre-flight per direction.
        if ("family_vault".equals(request.toMode())) {
            int wrapCount = dbClient.queryOne(SELECT_ACTIVE_WRAP_COUNT,
                    (rs, row) -> rs.getInt(1), creatorId).orElse(0);
            if (wrapCount < 1) {
                throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_WRAPS_REQUIRED,
                        "At least one active wrap is required before migrating into Family Vault");
            }
        }
        if ("family_vault".equals(request.fromMode())
                && ("model_a".equals(request.toMode()) || "model_b".equals(request.toMode()))) {
            if (request.recoveryBlobId() == null || request.recoveryBlobId().isBlank()) {
                throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_BLOB_REQUIRED,
                        "recoveryBlobId is required when migrating out of Family Vault");
            }
            if (dbClient.queryOne(SELECT_CURRENT_BLOB_EXISTS,
                    (rs, row) -> 1, creatorId, request.recoveryBlobId()).isEmpty()) {
                throw new AppException(ErrorCode.FAMILY_VAULT_MIGRATION_BLOB_REQUIRED,
                        "Recovery blob " + request.recoveryBlobId() + " is not the active blob for this creator");
            }
        }

        String migrationId = CsprngUtil.randomUlid();
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_MODE_MIGRATION_STARTED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(migrationId)
                .metadataJson(Map.of(
                        "migrationId", migrationId,
                        "fromMode", request.fromMode(),
                        "toMode", request.toMode()))
                .build());

        try {
            int[] effects = new int[]{0, 0};
            dbClient.withTransaction(status -> {
                if ("family_vault".equals(request.toMode())) {
                    int superseded = dbClient.execute(SUPERSEDE_CURRENT_BLOB, creatorId);
                    effects[1] = superseded;
                } else if ("family_vault".equals(request.fromMode())) {
                    int revoked = dbClient.execute(REVOKE_ALL_ACTIVE_WRAPS, creatorId);
                    effects[0] = revoked;
                }
                int updated = dbClient.execute(UPDATE_RECOVERY_MODE, request.toMode(), creatorId);
                if (updated != 1) {
                    throw new AppException(ErrorCode.INTERNAL_ERROR,
                            "Mode update affected " + updated + " rows");
                }
                return null;
            });

            Instant completedAt = Instant.now();
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.FAMILY_VAULT_MODE_MIGRATION_COMPLETED, AuditResult.SUCCESS)
                    .actorId(creatorId).actorType(PartyType.CREATOR).targetId(migrationId)
                    .metadataJson(Map.of(
                            "migrationId", migrationId,
                            "fromMode", request.fromMode(),
                            "toMode", request.toMode(),
                            "wrapsRevokedCount", effects[0],
                            "blobsSupersededCount", effects[1]))
                    .build());
            log.info("FV mode migration completed: migrationId={} creatorId={} {} → {} wrapsRevoked={} blobsSuperseded={}",
                    migrationId, creatorId, request.fromMode(), request.toMode(), effects[0], effects[1]);

            return ResponseEntity.ok(ApiResponse.ok(
                    new MigrateResponse(request.fromMode(), request.toMode(), migrationId,
                            completedAt, effects[0], effects[1]),
                    UUID.randomUUID().toString()));
        } catch (AppException ex) {
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.FAMILY_VAULT_MODE_MIGRATION_FAILED, AuditResult.FAILURE)
                    .actorId(creatorId).actorType(PartyType.CREATOR).targetId(migrationId)
                    .metadataJson(Map.of(
                            "migrationId", migrationId,
                            "errorCode", ex.getErrorCode().name(),
                            "message", ex.getMessage()))
                    .build());
            throw ex;
        } catch (Exception ex) {
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.FAMILY_VAULT_MODE_MIGRATION_FAILED, AuditResult.FAILURE)
                    .actorId(creatorId).actorType(PartyType.CREATOR).targetId(migrationId)
                    .metadataJson(Map.of(
                            "migrationId", migrationId,
                            "errorClass", ex.getClass().getSimpleName(),
                            "message", ex.getMessage() != null ? ex.getMessage() : ""))
                    .build());
            throw new AppException(ErrorCode.INTERNAL_ERROR, "Migration failed: " + ex.getMessage());
        }
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

    public record MigrateRequest(
            @NotBlank String fromMode,
            @NotBlank String toMode,
            String recoveryBlobId) {}

    public record MigrateResponse(String fromMode, String toMode, String migrationId,
            Instant completedAt, int wrapsRevokedCount, int blobsSupersededCount) {}
}
