package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * B-A6-4 (DEV/STAGING ONLY): inject a verified death signal without forging an HMAC-signed
 * webhook + the SQS round-trip, so the 2-of-3 → approved → recovery path is testable on
 * staging. Mirrors the consumer's threshold transitions (see sqs-consumer ThresholdService).
 *
 * <p><b>Guarded:</b> returns 404 whenever {@code ENVIRONMENT} is prod, so it is never reachable
 * in production. This is a test backdoor into the trigger system and must stay non-prod.
 */
@RestController
@RequestMapping("/trigger/dev")
public class DevInjectSourceHandler {

    private static final Logger log = LoggerFactory.getLogger(DevInjectSourceHandler.class);
    private static final int THRESHOLD = 2;
    private static final Set<String> ALLOWED_SOURCE_TYPES = Set.of(
            "death_registry", "municipality", "inactivity", "nominee_report", "lawyer_report");

    private static final String SELECT_USER_BY_MOBILE =
            "SELECT user_id FROM users WHERE mobile = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_ACTIVE_TRIGGER =
            "SELECT trigger_id, threshold_met FROM trigger_events WHERE creator_id = ? " +
            "AND status IN ('pending_threshold', 'threshold_met', 'approved') ORDER BY created_at DESC LIMIT 1";
    private static final String INSERT_TRIGGER =
            "INSERT INTO trigger_events (trigger_id, creator_id, status, threshold_met, created_at, updated_at) " +
            "VALUES (?, ?, 'pending_threshold', FALSE, NOW(), NOW())";
    private static final String INSERT_SOURCE =
            "INSERT INTO trigger_sources (source_id, trigger_id, source_type, reference_id, " +
            "verified, received_at, created_at) VALUES (?, ?, ?, ?, TRUE, NOW(), NOW())";
    private static final String SELECT_VERIFIED_COUNT =
            "SELECT COUNT(*) FROM trigger_sources WHERE trigger_id = ? AND verified = TRUE";
    private static final String UPDATE_APPROVED =
            "UPDATE trigger_events SET status = 'approved', threshold_met = TRUE, " +
            "threshold_met_at = NOW(), updated_at = NOW() WHERE trigger_id = ?";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<TriggerRow> TRIGGER_MAPPER = (rs, row) ->
            new TriggerRow(rs.getString("trigger_id"), rs.getBoolean("threshold_met"));

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    @Value("${ENVIRONMENT:local}")
    private String environment;

    /** Constructs DevInjectSourceHandler with required dependencies. */
    public DevInjectSourceHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /trigger/dev/inject-source — DEV/STAGING only; 404 in prod. */
    @PostMapping("/inject-source")
    public ResponseEntity<ApiResponse<Map<String, Object>>> inject(
            @RequestBody @Valid DevInjectSourceRequest request) {

        if (isProd()) {
            // Look like the route doesn't exist in production.
            throw AppException.notFound("resource");
        }

        String sourceType = request.sourceType().toLowerCase();
        if (!ALLOWED_SOURCE_TYPES.contains(sourceType)) {
            throw AppException.validationFailed(Map.of(
                    "sourceType", "Must be one of " + ALLOWED_SOURCE_TYPES));
        }

        String creatorId = dbClient.queryOne(SELECT_USER_BY_MOBILE, STRING_MAPPER, request.creatorMobile())
                .orElseThrow(() -> AppException.notFound("user"));

        TriggerRow trigger = dbClient.queryOne(SELECT_ACTIVE_TRIGGER, TRIGGER_MAPPER, creatorId)
                .orElseGet(() -> {
                    String triggerId = CsprngUtil.randomUlid();
                    dbClient.execute(INSERT_TRIGGER, triggerId, creatorId);
                    return new TriggerRow(triggerId, false);
                });

        try {
            dbClient.execute(INSERT_SOURCE, CsprngUtil.randomUlid(), trigger.triggerId(),
                    sourceType, "dev-inject-" + CsprngUtil.randomUlid());
        } catch (RuntimeException ex) {
            log.info("[DEV] Duplicate source ignored: triggerId={} sourceType={}",
                    trigger.triggerId(), sourceType);
        }

        int verifiedCount = dbClient.queryOne(SELECT_VERIFIED_COUNT, (rs, r) -> rs.getInt(1),
                trigger.triggerId()).orElse(0);

        boolean approved = trigger.thresholdMet();
        if (verifiedCount >= THRESHOLD && !trigger.thresholdMet()) {
            dbClient.execute(UPDATE_APPROVED, trigger.triggerId());
            approved = true;
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.TRIGGER_THRESHOLD_MET, AuditResult.SUCCESS)
                    .actorId(null).actorType(PartyType.SYSTEM).targetId(trigger.triggerId())
                    .metadataJson(Map.of("creatorId", creatorId, "via", "dev-inject"))
                    .build());
        }

        log.warn("[DEV] Source injected: creatorId={} triggerId={} sourceType={} count={}/{} approved={}",
                creatorId, trigger.triggerId(), sourceType, verifiedCount, THRESHOLD, approved);

        Map<String, Object> body = Map.of(
                "creatorId", creatorId,
                "triggerId", trigger.triggerId(),
                "sourceType", sourceType,
                "verifiedCount", verifiedCount,
                "thresholdMet", approved,
                "status", approved ? "approved" : "pending_threshold");
        return ResponseEntity.ok(ApiResponse.ok(body, UUID.randomUUID().toString()));
    }

    private boolean isProd() {
        return environment != null
                && (environment.equalsIgnoreCase("prod") || environment.equalsIgnoreCase("production"));
    }

    /** Request body: target creator's mobile + the death-signal source type. */
    public record DevInjectSourceRequest(
            @NotBlank String creatorMobile,
            @NotBlank String sourceType) {}

    private record TriggerRow(String triggerId, boolean thresholdMet) {}
}
