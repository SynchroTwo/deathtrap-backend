package in.deathtrap.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.sqs.SqsClient;

/** Sends blob rebuild notifications to SQS. Never throws — SQS failure only logs. */
@Component
public class BlobRebuildNotifier {

    private static final Logger log = LoggerFactory.getLogger(BlobRebuildNotifier.class);

    private final SqsClient sqsClient;

    @Value("${SQS_TRIGGER_URL:}")
    private String sqsTriggerUrl;

    @Value("${ENVIRONMENT:local}")
    private String environment;

    /** Constructs BlobRebuildNotifier with the AWS SQS client. */
    public BlobRebuildNotifier(SqsClient sqsClient) {
        this.sqsClient = sqsClient;
    }

    /** Sends a blob rebuild notification to SQS. Non-blocking: logs and returns if SQS not configured or send fails. */
    public void notifyRebuildRequired(String creatorId, String reason, String partyId, String partyType) {
        if (sqsTriggerUrl == null || sqsTriggerUrl.isBlank()
                || "staging".equals(environment)) {
            log.warn("[DEV/STAGING] Blob rebuild required: creatorId={}", creatorId);
            return;
        }
        try {
            String messageBody = String.format(
                    "{\"event\":\"BLOB_REBUILD_REQUIRED\",\"creatorId\":\"%s\"," +
                    "\"reason\":\"%s\",\"partyId\":\"%s\",\"partyType\":\"%s\"}",
                    creatorId, reason, partyId, partyType);
            sqsClient.sendMessage(b -> b.queueUrl(sqsTriggerUrl).messageBody(messageBody));
            log.info("Blob rebuild SQS message sent: creatorId={} reason={}", creatorId, reason);
        } catch (Exception e) {
            log.error("Failed to send blob rebuild SQS message: creatorId={} error={}", creatorId, e.getMessage(), e);
        }
    }
}
