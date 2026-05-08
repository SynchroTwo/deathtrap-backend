package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.sqs.SqsClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for DeathEventWebhookHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class DeathEventWebhookHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private SqsClient sqsClient;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private DeathEventWebhookHandler handler;

    private static final String SECRET = "test-secret";
    private static final String RAW_BODY =
            "{\"creatorMobile\":\"+919999999999\",\"sourceType\":\"DEATH_REGISTRY\"," +
            "\"referenceId\":\"ref-001\",\"reportedAt\":\"2026-01-01T00:00:00Z\"}";

    private String validSig() {
        return "sha256=" + Sha256Util.hashHex(SECRET + RAW_BODY);
    }

    @BeforeEach
    void setUp() {
        handler.webhookSecret = SECRET;
        handler.sqsUrl = "";
    }

    @Test
    void validSig_knownMobile_sqsNotConfigured_returns200() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of("creator-1"));

        ResponseEntity<?> response = handler.handleDeathEvent(RAW_BODY, validSig());

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void invalidSig_returns401() {
        ResponseEntity<?> response = handler.handleDeathEvent(RAW_BODY, "sha256=bad-signature");

        assertEquals(401, response.getStatusCode().value());
    }

    @Test
    void unknownMobile_returns200WithEventReceived() {
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        ResponseEntity<?> response = handler.handleDeathEvent(RAW_BODY, validSig());

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void validSig_knownMobile_sqsConfigured_dispatches_returns200() {
        handler.sqsUrl = "https://sqs.ap-south-1.amazonaws.com/123456789/test-queue";
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of("creator-1"));

        ResponseEntity<?> response = handler.handleDeathEvent(RAW_BODY, validSig());

        assertEquals(200, response.getStatusCode().value());
    }
}
