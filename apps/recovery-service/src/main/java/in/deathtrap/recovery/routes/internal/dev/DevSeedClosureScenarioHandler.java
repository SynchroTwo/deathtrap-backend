package in.deathtrap.recovery.routes.internal.dev;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

/** E011 Phase 1C §9.3 — staging-only dev endpoint that seeds account_closure
 *  state into one of five canonical scenarios so the closure round-trip can
 *  be exercised end-to-end without orchestrating three real nominee uploads.
 *  Same protection model as §9.2 dev-mint: DEV_ENDPOINTS_ENABLED gate +
 *  HMAC X-Internal-Token. Audits every scenario. */
@RestController
@RequestMapping("/recovery/internal/dev")
public class DevSeedClosureScenarioHandler {

    private static final Logger log = LoggerFactory.getLogger(DevSeedClosureScenarioHandler.class);
    private static final String INTERNAL_HEADER = "X-Internal-Token";

    // Look-ups.
    private static final String SELECT_OPEN_CLOSURE_ID =
            "SELECT closure_id FROM account_closure WHERE creator_id = ? " +
            "AND status IN ('pending_objection', 'finalising') LIMIT 1";
    private static final String SELECT_ACTIVE_WRAP_NOMINEES =
            "SELECT nominee_party_id FROM family_vault_wraps WHERE creator_id = ? " +
            "AND status = 'active' LIMIT 3";
    private static final String EXISTS_CREATOR =
            "SELECT 1 FROM users WHERE user_id = ? LIMIT 1";

    // Mutations.
    private static final String INSERT_CERT =
            "INSERT INTO death_cert_uploads (cert_id, creator_id, uploader_party_id, " +
            "uploader_party_type, s3_key, mime_type, size_bytes, content_hash_sha256, uploaded_at) " +
            "VALUES (?, ?, ?, 'nominee'::party_type_enum, ?, 'application/pdf', 1024, ?, NOW())";
    private static final String INSERT_PENDING_CLOSURE =
            "INSERT INTO account_closure (closure_id, creator_id, trigger_kind, trigger_context_json, " +
            "objection_window_ends_at, status) " +
            "VALUES (?, ?, ?::account_closure_trigger, ?::jsonb, ?, 'pending_objection')";
    private static final String INSERT_FINALISED_CLOSED =
            "INSERT INTO account_closure (closure_id, creator_id, trigger_kind, trigger_context_json, " +
            "objection_window_ends_at, status, finalised_at, archive_complete_at, archive_bucket, " +
            "archive_s3_prefix, archive_object_count) " +
            "VALUES (?, ?, 'three_cert_threshold', ?::jsonb, NOW() - INTERVAL '1 minute', 'closed', " +
            "NOW() - INTERVAL '1 minute', NOW(), ?, ?, 0)";
    private static final String CANCEL_OPEN_CLOSURES =
            "UPDATE account_closure SET status = 'cancelled', cancelled_at = NOW(), " +
            "cancelled_reason = 'dev_scenario_reset' " +
            "WHERE creator_id = ? AND status IN ('pending_objection', 'finalising')";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<String> NOMINEE_MAPPER = (rs, row) -> rs.getString("nominee_party_id");

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    @Value("${DEV_ENDPOINTS_ENABLED:false}")
    private String devEndpointsEnabled;

    @Value("${INTERNAL_WORKER_SECRET:}")
    private String internalWorkerSecret;

    @Value("${S3_BUCKET_NAME:dev-bucket}")
    private String s3BucketName;

    public DevSeedClosureScenarioHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /recovery/internal/dev/seed-closure-scenario — see contract §9.3. */
    @PostMapping("/seed-closure-scenario")
    public ResponseEntity<ApiResponse<SeedResponse>> seedScenario(
            @RequestBody @Valid SeedRequest request,
            @RequestHeader(value = INTERNAL_HEADER, required = false) String internalToken,
            @RequestHeader(value = "X-Forwarded-For", required = false) String sourceIp) {

        assertDevEnabled();
        assertInternalAuth(internalToken);
        assertCreatorExists(request.creatorId());

        StateAfter state = switch (request.scenario()) {
            case "three_cert_threshold_open" -> seedThreeCertThreshold(request.creatorId());
            case "pending_objection_window" -> seedPendingObjection(request.creatorId(), "missed_payment_grace");
            case "expire_window_immediately" -> seedExpireImmediately(request.creatorId());
            case "finalise_and_close" -> seedFinaliseAndClose(request.creatorId());
            case "reset_creator_closures" -> seedReset(request.creatorId());
            default -> throw AppException.validationFailed(Map.of(
                    "field", "scenario",
                    "message", "Unknown scenario: " + request.scenario()));
        };

        String auditEventId = CsprngUtil.randomUlid();
        Map<String, Object> auditMeta = new HashMap<>(Map.of(
                "creatorId", request.creatorId(),
                "scenario", request.scenario(),
                "sourceIp", sourceIp != null ? sourceIp : "unknown"));
        if (state.closureId() != null) {
            auditMeta.put("closureId", state.closureId());
        }
        if (state.status() != null) {
            auditMeta.put("status", state.status());
        }
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.DEV_SCENARIO_SEEDED, AuditResult.SUCCESS)
                .actorType(PartyType.SYSTEM).targetId(auditEventId)
                .metadataJson(auditMeta)
                .build());
        log.info("Dev scenario seeded: scenario={} creatorId={} closureId={} status={}",
                request.scenario(), request.creatorId(), state.closureId(), state.status());

        return ResponseEntity.ok(ApiResponse.ok(
                new SeedResponse(request.scenario(), request.creatorId(), state, auditEventId),
                UUID.randomUUID().toString()));
    }

    private StateAfter seedThreeCertThreshold(String creatorId) {
        // Need 3 distinct active-wrap nominees to act as uploaders.
        List<String> nominees = dbClient.query(SELECT_ACTIVE_WRAP_NOMINEES, NOMINEE_MAPPER, creatorId);
        if (nominees.size() < 3) {
            throw new AppException(ErrorCode.CONFLICT,
                    "Creator needs at least 3 active family_vault_wraps for this scenario; have "
                            + nominees.size());
        }
        // Insert 3 cert rows.
        String s3Key = "recovery/death-certs/" + creatorId + "/dev-";
        for (int i = 0; i < 3; i++) {
            String certId = CsprngUtil.randomUlid();
            dbClient.execute(INSERT_CERT,
                    certId, creatorId, nominees.get(i), s3Key + certId,
                    "deadbeef".repeat(8));
        }
        // Open the closure.
        return openPendingObjectionRow(creatorId, "three_cert_threshold", 30);
    }

    private StateAfter seedPendingObjection(String creatorId, String triggerKind) {
        return openPendingObjectionRow(creatorId, triggerKind, 30);
    }

    private StateAfter seedExpireImmediately(String creatorId) {
        Optional<String> existing = dbClient.queryOne(SELECT_OPEN_CLOSURE_ID, STRING_MAPPER, creatorId);
        if (existing.isPresent()) {
            throw new AppException(ErrorCode.CONFLICT,
                    "Open closure already exists for creator: " + existing.get());
        }
        String closureId = CsprngUtil.randomUlid();
        Instant past = Instant.now().minusSeconds(60);
        dbClient.execute(INSERT_PENDING_CLOSURE,
                closureId, creatorId, "three_cert_threshold",
                "{\"scenario\":\"expire_window_immediately\"}",
                Timestamp.from(past));
        return new StateAfter(closureId, "pending_objection", past);
    }

    private StateAfter seedFinaliseAndClose(String creatorId) {
        Optional<String> existing = dbClient.queryOne(SELECT_OPEN_CLOSURE_ID, STRING_MAPPER, creatorId);
        if (existing.isPresent()) {
            throw new AppException(ErrorCode.CONFLICT,
                    "Open closure already exists for creator: " + existing.get());
        }
        String closureId = CsprngUtil.randomUlid();
        String archivePrefix = "archive/closure/" + closureId + "/";
        dbClient.execute(INSERT_FINALISED_CLOSED,
                closureId, creatorId,
                "{\"scenario\":\"finalise_and_close\"}",
                s3BucketName, archivePrefix);
        return new StateAfter(closureId, "closed", null);
    }

    private StateAfter seedReset(String creatorId) {
        int updated = dbClient.execute(CANCEL_OPEN_CLOSURES, creatorId);
        log.info("Cancelled {} open closures for creator {}", updated, creatorId);
        return new StateAfter(null, null, null);
    }

    private StateAfter openPendingObjectionRow(String creatorId, String triggerKind, int windowDays) {
        Optional<String> existing = dbClient.queryOne(SELECT_OPEN_CLOSURE_ID, STRING_MAPPER, creatorId);
        if (existing.isPresent()) {
            throw new AppException(ErrorCode.CONFLICT,
                    "Open closure already exists for creator: " + existing.get());
        }
        String closureId = CsprngUtil.randomUlid();
        Instant windowEnds = Instant.now().plus(java.time.Duration.ofDays(windowDays));
        dbClient.execute(INSERT_PENDING_CLOSURE,
                closureId, creatorId, triggerKind,
                "{\"scenario\":\"dev-seed\",\"trigger\":\"" + triggerKind + "\"}",
                Timestamp.from(windowEnds));
        return new StateAfter(closureId, "pending_objection", windowEnds);
    }

    private void assertDevEnabled() {
        if (!"true".equalsIgnoreCase(devEndpointsEnabled)) {
            throw new AppException(ErrorCode.DEV_ENDPOINT_DISABLED,
                    "Dev endpoints disabled (DEV_ENDPOINTS_ENABLED is not 'true')");
        }
    }

    private void assertInternalAuth(String providedToken) {
        if (internalWorkerSecret == null || internalWorkerSecret.isBlank()) {
            log.warn("Internal worker secret not configured; rejecting dev-seed call");
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Internal worker not configured");
        }
        if (providedToken == null) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Missing internal token");
        }
        byte[] expected = internalWorkerSecret.getBytes();
        byte[] provided = providedToken.getBytes();
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Internal token mismatch");
        }
    }

    private void assertCreatorExists(String creatorId) {
        if (dbClient.queryOne(EXISTS_CREATOR, (rs, row) -> 1, creatorId).isEmpty()) {
            throw AppException.notFound("creator");
        }
    }

    public record SeedRequest(@NotBlank String creatorId, @NotBlank String scenario) {}

    public record StateAfter(String closureId, String status, Instant objectionWindowEndsAt) {}

    public record SeedResponse(String scenario, String creatorId, StateAfter stateAfter, String auditEventId) {}
}
