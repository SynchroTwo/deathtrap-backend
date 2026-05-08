package in.deathtrap.sqsconsumer.service;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.sqsconsumer.rowmapper.TriggerEventRowMapper;
import in.deathtrap.sqsconsumer.rowmapper.TriggerEventRowMapper.TriggerEvent;
import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Applies the 2-of-3 death signal threshold and triggers notifications when met. */
@Service
public class ThresholdService {

    private static final Logger log = LoggerFactory.getLogger(ThresholdService.class);
    private static final int THRESHOLD = 2;

    private static final String SELECT_ACTIVE_TRIGGER =
            "SELECT trigger_id, creator_id, status, threshold_met, threshold_met_at, created_at " +
            "FROM trigger_events WHERE creator_id = ? " +
            "AND status IN ('pending_threshold', 'threshold_met') ORDER BY created_at DESC LIMIT 1";
    private static final String INSERT_TRIGGER =
            "INSERT INTO trigger_events (trigger_id, creator_id, status, threshold_met, created_at, updated_at) " +
            "VALUES (?, ?, 'pending_threshold', FALSE, NOW(), NOW())";
    private static final String INSERT_SOURCE =
            "INSERT INTO trigger_sources (source_id, trigger_id, source_type, reference_id, " +
            "verified, received_at, created_at) VALUES (?, ?, ?, ?, TRUE, NOW(), NOW())";
    private static final String SELECT_VERIFIED_COUNT =
            "SELECT COUNT(*) FROM trigger_sources WHERE trigger_id = ? AND verified = TRUE";
    private static final String UPDATE_THRESHOLD_MET =
            "UPDATE trigger_events SET status = 'threshold_met', threshold_met = TRUE, " +
            "threshold_met_at = NOW(), updated_at = NOW() WHERE trigger_id = ?";

    private final DbClient db;
    private final NotificationDispatcher notifications;
    private final AuditWriter auditWriter;

    /** Constructs ThresholdService with required dependencies. */
    public ThresholdService(DbClient db, NotificationDispatcher notifications, AuditWriter auditWriter) {
        this.db = db;
        this.notifications = notifications;
        this.auditWriter = auditWriter;
    }

    /** Processes a death signal, records the source, and triggers notifications if threshold met. */
    @Transactional
    public void processDeathSignal(String creatorId, String sourceType, String referenceId) {
        TriggerEvent trigger = getOrCreateTriggerEvent(creatorId);

        try {
            db.execute(INSERT_SOURCE,
                    CsprngUtil.randomUlid(), trigger.triggerId(),
                    sourceType != null ? sourceType.toLowerCase() : null, referenceId);
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.TRIGGER_SOURCE_RECEIVED, AuditResult.SUCCESS)
                    .actorId(null).actorType(PartyType.SYSTEM)
                    .targetId(trigger.triggerId())
                    .metadataJson(Map.of("sourceType", String.valueOf(sourceType),
                            "referenceId", String.valueOf(referenceId)))
                    .build());
        } catch (Exception e) {
            log.info("Duplicate trigger source ignored: triggerId={} sourceType={}",
                    trigger.triggerId(), sourceType);
        }

        int verifiedCount = db.queryOne(SELECT_VERIFIED_COUNT,
                (rs, r) -> rs.getInt(1), trigger.triggerId()).orElse(0);

        log.info("Verified sources for creatorId={}: {}/{}", creatorId, verifiedCount, THRESHOLD);

        if (verifiedCount >= THRESHOLD && !trigger.thresholdMet()) {
            markThresholdMet(trigger.triggerId(), creatorId);
        }
    }

    private TriggerEvent getOrCreateTriggerEvent(String creatorId) {
        return db.queryOne(SELECT_ACTIVE_TRIGGER, TriggerEventRowMapper.INSTANCE, creatorId)
                .orElseGet(() -> {
                    String triggerId = CsprngUtil.randomUlid();
                    db.execute(INSERT_TRIGGER, triggerId, creatorId);
                    return new TriggerEvent(triggerId, creatorId, "pending_threshold",
                            false, null, Instant.now());
                });
    }

    private void markThresholdMet(String triggerId, String creatorId) {
        db.execute(UPDATE_THRESHOLD_MET, triggerId);

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.TRIGGER_THRESHOLD_MET, AuditResult.SUCCESS)
                .actorId(null).actorType(PartyType.SYSTEM)
                .targetId(triggerId)
                .metadataJson(Map.of("creatorId", creatorId))
                .build());

        notifications.notifyAdminThresholdMet(creatorId, triggerId);
        notifications.notifyCreatorThresholdMet(creatorId);
        notifications.notifyPartiesThresholdMet(creatorId);

        log.warn("Death threshold MET for creatorId={} triggerId={}", creatorId, triggerId);
    }
}
