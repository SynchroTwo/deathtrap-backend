package in.deathtrap.trigger.service;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper.InactivityCheck;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.sqs.SqsClient;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for InactivityService — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class InactivityServiceTest {

    @Mock private DbClient db;
    @Mock private NotificationService notifications;
    @Mock private SqsClient sqsClient;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private InactivityService service;

    private InactivityCheck check(int alertsSent) {
        return new InactivityCheck("chk-1", "creator-1",
                Instant.now().minusSeconds(86400), Instant.now().minusSeconds(1),
                alertsSent, false, Instant.now().minusSeconds(3600), Instant.now().minusSeconds(3600));
    }

    @Test
    void alertsSent0_sendsFirstAlertAndUpdatesDb() {
        when(db.query(anyString(), any())).thenReturn((List) List.of(check(0)));

        service.scanAndEscalate();

        verify(notifications).sendInactivityAlert("creator-1", 1);
    }

    @Test
    void alertsSent1_sendsSecondAlertAndReschedules() {
        when(db.query(anyString(), any())).thenReturn((List) List.of(check(1)));

        service.scanAndEscalate();

        verify(notifications).sendInactivityAlert("creator-1", 2);
    }

    @Test
    void alertsSent2_sqsConfigured_dispatchesTrigger() {
        service.sqsTriggerUrl = "https://sqs.ap-south-1.amazonaws.com/123/test";
        when(db.query(anyString(), any())).thenReturn((List) List.of(check(2)));

        service.scanAndEscalate();

        verify(sqsClient).sendMessage(any(java.util.function.Consumer.class));
    }

    @Test
    void alertsSent2_sqsNotConfigured_logsAndDoesNotThrow() {
        service.sqsTriggerUrl = "";
        when(db.query(anyString(), any())).thenReturn((List) List.of(check(2)));

        assertDoesNotThrow(() -> service.scanAndEscalate());
    }

    @Test
    void oneCheckFails_otherCheckStillProcessed() {
        InactivityCheck failCheck = new InactivityCheck("chk-fail", "fail-creator",
                Instant.now().minusSeconds(86400), Instant.now().minusSeconds(1),
                0, false, Instant.now().minusSeconds(3600), Instant.now().minusSeconds(3600));
        InactivityCheck okCheck = check(0);
        when(db.query(anyString(), any())).thenReturn((List) List.of(failCheck, okCheck));
        doThrow(new RuntimeException("SMS failed"))
                .when(notifications).sendInactivityAlert(eq("fail-creator"), any(int.class));

        assertDoesNotThrow(() -> service.scanAndEscalate());
        verify(notifications).sendInactivityAlert("creator-1", 1);
    }
}
