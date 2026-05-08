package in.deathtrap.trigger.routes;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.DeathEventWebhookRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
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
import software.amazon.awssdk.services.sqs.SqsClient;

/** Handles POST /trigger/event — receives death event webhooks from external registries. */
@RestController
@RequestMapping("/trigger/event")
public class DeathEventWebhookHandler {

    private static final Logger log = LoggerFactory.getLogger(DeathEventWebhookHandler.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SELECT_USER_BY_MOBILE =
            "SELECT user_id FROM users WHERE mobile = ? AND status = 'active' LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final SqsClient sqsClient;
    private final AuditWriter auditWriter;

    @Value("${WEBHOOK_SECRET:}")
    String webhookSecret;

    @Value("${SQS_TRIGGER_URL:}")
    String sqsUrl;

    /** Constructs DeathEventWebhookHandler with required dependencies. */
    public DeathEventWebhookHandler(DbClient dbClient, SqsClient sqsClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.sqsClient = sqsClient;
        this.auditWriter = auditWriter;
    }

    /** POST /trigger/event — validates HMAC signature and dispatches death event to SQS. */
    @PostMapping
    public ResponseEntity<ApiResponse<Map<String, String>>> handleDeathEvent(
            @RequestBody String rawBody,
            @RequestHeader("X-Webhook-Signature") String signature) {

        String expectedSig = "sha256=" + Sha256Util.hashHex(webhookSecret + rawBody);
        if (!MessageDigest.isEqual(
                expectedSig.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            log.warn("Webhook signature mismatch");
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.TRIGGER_SOURCE_RECEIVED, AuditResult.FAILURE)
                    .actorId(null).actorType(PartyType.SYSTEM)
                    .failureReason("Invalid webhook signature")
                    .build());
            return ResponseEntity.status(401).body(ApiResponse.error(null, UUID.randomUUID().toString()));
        }

        DeathEventWebhookRequest request;
        try {
            request = MAPPER.readValue(rawBody, DeathEventWebhookRequest.class);
        } catch (Exception e) {
            log.error("Failed to parse webhook body: {}", e.getMessage());
            return ResponseEntity.badRequest().body(ApiResponse.error(null, UUID.randomUUID().toString()));
        }

        List<String> users = dbClient.query(SELECT_USER_BY_MOBILE, STRING_MAPPER, request.creatorMobile());
        if (users.isEmpty()) {
            log.warn("Death event received for unknown mobile: {}", request.creatorMobile());
            return ResponseEntity.ok(ApiResponse.ok(
                    Map.of("message", "Event received"), UUID.randomUUID().toString()));
        }
        String creatorId = users.get(0);

        String messageJson = String.format(
                "{\"event\":\"DEATH_EVENT\",\"creatorId\":\"%s\",\"sourceType\":\"%s\"," +
                "\"referenceId\":\"%s\",\"reportedAt\":\"%s\"}",
                creatorId, request.sourceType(), request.referenceId(), request.reportedAt());

        if (sqsUrl == null || sqsUrl.isBlank()) {
            log.warn("[DEV] SQS dispatch skipped for creatorId={}", creatorId);
        } else {
            try {
                sqsClient.sendMessage(b -> b.queueUrl(sqsUrl).messageBody(messageJson));
            } catch (Exception e) {
                log.error("Failed to dispatch death event to SQS: creatorId={} error={}", creatorId, e.getMessage(), e);
            }
        }

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.TRIGGER_SOURCE_RECEIVED, AuditResult.SUCCESS)
                .actorId(null).actorType(PartyType.SYSTEM)
                .targetId(creatorId)
                .metadataJson(Map.of("sourceType", request.sourceType(),
                        "referenceId", request.referenceId()))
                .build());

        log.info("Death event received: creatorId={} sourceType={}", creatorId, request.sourceType());

        return ResponseEntity.ok(ApiResponse.ok(
                Map.of("message", "Event received"), UUID.randomUUID().toString()));
    }
}
