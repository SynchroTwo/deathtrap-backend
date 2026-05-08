package in.deathtrap.trigger.service;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper.InactivityCheck;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sqs.SqsClient;

/** Scans for overdue inactivity checks and escalates through alert stages. */
@Service
public class InactivityService {

    private static final Logger log = LoggerFactory.getLogger(InactivityService.class);

    private static final String SELECT_OVERDUE =
            "SELECT * FROM inactivity_checks WHERE next_check_at < NOW() AND triggered = FALSE";
    private static final String UPDATE_ALERTS_SENT =
            "UPDATE inactivity_checks SET alerts_sent = ?, updated_at = NOW() WHERE check_id = ?";
    private static final String UPDATE_RESCHEDULE =
            "UPDATE inactivity_checks SET next_check_at = NOW() + INTERVAL '7 days', updated_at = NOW() WHERE check_id = ?";
    private static final String UPDATE_TRIGGERED =
            "UPDATE inactivity_checks SET triggered = TRUE, updated_at = NOW() WHERE check_id = ?";

    private final DbClient db;
    private final NotificationService notifications;
    private final SqsClient sqsClient;
    private final AuditWriter auditWriter;

    @Value("${SQS_TRIGGER_URL:}")
    String sqsTriggerUrl;

    /** Constructs InactivityService with required dependencies. */
    public InactivityService(DbClient db, NotificationService notifications,
            SqsClient sqsClient, AuditWriter auditWriter) {
        this.db = db;
        this.notifications = notifications;
        this.sqsClient = sqsClient;
        this.auditWriter = auditWriter;
    }

    /** Scans all overdue inactivity checks and processes each through the 3-stage escalation. */
    public void scanAndEscalate() {
        log.info("Inactivity scan starting: {}", Instant.now());
        List<InactivityCheck> dueChecks = db.query(SELECT_OVERDUE, InactivityCheckRowMapper.INSTANCE);
        log.info("Found {} overdue inactivity checks", dueChecks.size());
        for (InactivityCheck check : dueChecks) {
            try {
                processOneCheck(check);
            } catch (Exception e) {
                log.error("Failed to process inactivity check: creatorId={} error={}",
                        check.creatorId(), e.getMessage(), e);
            }
        }
    }

    private void processOneCheck(InactivityCheck check) {
        int alertsSent = check.alertsSent();
        if (alertsSent == 0) {
            notifications.sendInactivityAlert(check.creatorId(), 1);
            db.execute(UPDATE_ALERTS_SENT, 1, check.checkId());
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.INACTIVITY_CHECK_SENT, AuditResult.SUCCESS)
                    .actorId(null).actorType(PartyType.SYSTEM)
                    .targetId(check.creatorId())
                    .metadataJson(Map.of("alertNumber", 1))
                    .build());
        } else if (alertsSent == 1) {
            notifications.sendInactivityAlert(check.creatorId(), 2);
            db.execute(UPDATE_ALERTS_SENT, 2, check.checkId());
            db.execute(UPDATE_RESCHEDULE, check.checkId());
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.INACTIVITY_CHECK_SENT, AuditResult.SUCCESS)
                    .actorId(null).actorType(PartyType.SYSTEM)
                    .targetId(check.creatorId())
                    .metadataJson(Map.of("alertNumber", 2))
                    .build());
        } else {
            log.warn("Inactivity threshold breached: creatorId={}", check.creatorId());
            dispatchInactivityTrigger(check.creatorId());
            db.execute(UPDATE_TRIGGERED, check.checkId());
        }
    }

    private void dispatchInactivityTrigger(String creatorId) {
        if (sqsTriggerUrl == null || sqsTriggerUrl.isBlank()) {
            log.warn("[DEV] Inactivity trigger would be dispatched for creatorId={}", creatorId);
            return;
        }
        try {
            String body = String.format(
                    "{\"event\":\"INACTIVITY_TRIGGER\",\"creatorId\":\"%s\",\"sourceType\":\"inactivity\"}",
                    creatorId);
            sqsClient.sendMessage(b -> b.queueUrl(sqsTriggerUrl).messageBody(body));
        } catch (Exception e) {
            log.error("Failed to dispatch inactivity trigger to SQS: creatorId={} error={}",
                    creatorId, e.getMessage(), e);
        }
    }
}
