package in.deathtrap.sqsconsumer.service;

import in.deathtrap.common.db.DbClient;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

/** Dispatches SNS/SMS notifications when the death threshold is met. */
@Service
public class NotificationDispatcher {

    private static final Logger log = LoggerFactory.getLogger(NotificationDispatcher.class);

    private static final String SELECT_CREATOR_MOBILE =
            "SELECT mobile FROM users WHERE user_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_NOMINEE_MOBILES =
            "SELECT u.mobile FROM nominees n JOIN users u ON n.nominee_id = u.user_id " +
            "WHERE n.creator_id = ? AND n.status = 'active'";
    private static final String SELECT_LAWYER_MOBILE =
            "SELECT u.mobile FROM locker_meta lm " +
            "JOIN users u ON lm.assigned_lawyer_id = u.user_id " +
            "WHERE lm.user_id = ? AND u.status = 'active' LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient db;
    private final SnsClient snsClient;

    @Value("${SNS_NOTIFY_ARN:}")
    private String snsNotifyArn;

    /** Constructs NotificationDispatcher with required dependencies. */
    public NotificationDispatcher(DbClient db, SnsClient snsClient) {
        this.db = db;
        this.snsClient = snsClient;
    }

    /** Publishes admin action-required notification to the SNS admin topic. Never throws. */
    public void notifyAdminThresholdMet(String creatorId, String triggerId) {
        try {
            if (snsNotifyArn == null || snsNotifyArn.isBlank()) {
                log.warn("[DEV] Admin notification skipped: creatorId={} triggerId={}", creatorId, triggerId);
                return;
            }
            String message = toJson(Map.of(
                    "type", "ADMIN_ACTION_REQUIRED",
                    "action", "APPROVE_TRIGGER",
                    "creatorId", creatorId,
                    "triggerId", triggerId));
            snsClient.publish(PublishRequest.builder()
                    .topicArn(snsNotifyArn)
                    .message(message)
                    .build());
            log.info("Admin notified of threshold: creatorId={} triggerId={}", creatorId, triggerId);
        } catch (Exception e) {
            log.error("Failed to notify admin: creatorId={} triggerId={} error={}",
                    creatorId, triggerId, e.getMessage(), e);
        }
    }

    /** Sends SMS to creator warning of confirmed death report. Never throws. */
    public void notifyCreatorThresholdMet(String creatorId) {
        try {
            List<String> mobiles = db.query(SELECT_CREATOR_MOBILE, STRING_MAPPER, creatorId);
            if (mobiles.isEmpty()) { return; }
            String message = "DeathTrap: A death report has been filed and confirmed for your account. " +
                    "If you are alive, please open the app immediately and check in or halt the recovery process.";
            publishSms(mobiles.get(0), message);
        } catch (Exception e) {
            log.error("Failed to notify creator: creatorId={} error={}", creatorId, e.getMessage(), e);
        }
    }

    /** Sends SMS to all active nominees and the assigned lawyer. Never throws. */
    public void notifyPartiesThresholdMet(String creatorId) {
        try {
            List<String> nomineeMobiles = db.query(SELECT_NOMINEE_MOBILES, STRING_MAPPER, creatorId);
            List<String> lawyerMobiles = db.query(SELECT_LAWYER_MOBILE, STRING_MAPPER, creatorId);
            String message = "DeathTrap: You have been identified as a beneficiary. " +
                    "The death of the account holder has been confirmed. " +
                    "You may be contacted soon to begin the recovery process.";
            for (String mobile : nomineeMobiles) {
                try { publishSms(mobile, message); } catch (Exception e) {
                    log.error("Failed to SMS nominee mobile={} error={}", mobile, e.getMessage());
                }
            }
            for (String mobile : lawyerMobiles) {
                try { publishSms(mobile, message); } catch (Exception e) {
                    log.error("Failed to SMS lawyer mobile={} error={}", mobile, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to notify parties: creatorId={} error={}", creatorId, e.getMessage(), e);
        }
    }

    private void publishSms(String phoneNumber, String message) {
        if (snsNotifyArn == null || snsNotifyArn.isBlank()) {
            log.warn("[DEV] SMS skipped: to={}", phoneNumber);
            return;
        }
        snsClient.publish(PublishRequest.builder()
                .phoneNumber(phoneNumber)
                .message(message)
                .build());
    }

    private String toJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder("{");
        map.forEach((k, v) -> sb.append("\"").append(k).append("\":\"").append(v).append("\","));
        if (sb.charAt(sb.length() - 1) == ',') { sb.deleteCharAt(sb.length() - 1); }
        sb.append("}");
        return sb.toString();
    }
}
