package in.deathtrap.trigger.service;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

import in.deathtrap.common.db.DbClient;

/** Sends SMS and push notifications to creators, nominees, and lawyers via AWS SNS. */
@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

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

    /** Constructs NotificationService with required dependencies. */
    public NotificationService(DbClient db, SnsClient snsClient) {
        this.db = db;
        this.snsClient = snsClient;
    }

    /** Sends an inactivity alert SMS to the creator. Never throws — logs all failures. */
    public void sendInactivityAlert(String creatorId, int alertNumber) {
        try {
            List<String> mobiles = db.query(SELECT_CREATOR_MOBILE, STRING_MAPPER, creatorId);
            if (mobiles.isEmpty()) {
                log.warn("Cannot send inactivity alert: no mobile for creatorId={}", creatorId);
                return;
            }
            String mobile = mobiles.get(0);
            String message = "DeathTrap: This is inactivity alert #" + alertNumber +
                    ". Please open the app and check in to confirm you are active. " +
                    "If you do not respond, your nominated beneficiaries may be notified.";
            publishSms(mobile, message);
        } catch (Exception e) {
            log.error("Failed to send inactivity alert: creatorId={} alert={} error={}",
                    creatorId, alertNumber, e.getMessage(), e);
        }
    }

    /** Publishes an admin action-required notification to the SNS admin topic. Never throws. */
    public void notifyAdminThresholdMet(String creatorId, String triggerId) {
        try {
            if (snsNotifyArn == null || snsNotifyArn.isBlank()) {
                log.warn("[DEV] Admin threshold notification skipped: creatorId={} triggerId={}",
                        creatorId, triggerId);
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
        } catch (Exception e) {
            log.error("Failed to notify admin: creatorId={} triggerId={} error={}",
                    creatorId, triggerId, e.getMessage(), e);
        }
    }

    /** Sends a threshold-met SMS to the creator. Never throws. */
    public void notifyCreatorThresholdMet(String creatorId) {
        try {
            List<String> mobiles = db.query(SELECT_CREATOR_MOBILE, STRING_MAPPER, creatorId);
            if (mobiles.isEmpty()) { return; }
            String message = "DeathTrap: A death report has been filed and confirmed for your account. " +
                    "If you are alive, please open the app immediately and check in or halt the recovery process.";
            publishSms(mobiles.get(0), message);
        } catch (Exception e) {
            log.error("Failed to notify creator of threshold: creatorId={} error={}", creatorId, e.getMessage(), e);
        }
    }

    /** Sends threshold-met SMS to all active nominees and the assigned lawyer. Never throws. */
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
            log.warn("[DEV] SMS skipped: to={} message={}", phoneNumber, message);
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
