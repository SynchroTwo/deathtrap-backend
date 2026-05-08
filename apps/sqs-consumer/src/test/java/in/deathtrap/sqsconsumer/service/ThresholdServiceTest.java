package in.deathtrap.sqsconsumer.service;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.sqsconsumer.rowmapper.TriggerEventRowMapper.TriggerEvent;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for ThresholdService — no Spring context, @Transactional ignored. */
@ExtendWith(MockitoExtension.class)
class ThresholdServiceTest {

    @Mock private DbClient db;
    @Mock private NotificationDispatcher notifications;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private ThresholdService service;

    private TriggerEvent pendingTrigger() {
        return new TriggerEvent("trg-1", "creator-1", "pending_threshold",
                false, null, Instant.now());
    }

    private TriggerEvent thresholdMetTrigger() {
        return new TriggerEvent("trg-1", "creator-1", "threshold_met",
                true, Instant.now(), Instant.now());
    }

    @Test
    void noActiveTrigger_createsNewTrigger_countBelowThreshold_noNotifications() {
        when(db.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(1));

        service.processDeathSignal("creator-1", "DEATH_REGISTRY", "ref-001");

        verify(notifications, never()).notifyAdminThresholdMet(anyString(), anyString());
    }

    @Test
    void existingTrigger_countMeetsThreshold_notifiesAll() {
        when(db.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.of(pendingTrigger()))
                .thenReturn(Optional.of(2));

        service.processDeathSignal("creator-1", "MUNICIPALITY", "ref-002");

        verify(notifications).notifyAdminThresholdMet("creator-1", "trg-1");
        verify(notifications).notifyCreatorThresholdMet("creator-1");
        verify(notifications).notifyPartiesThresholdMet("creator-1");
    }

    @Test
    void thresholdAlreadyMet_doesNotRenotify() {
        when(db.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.of(thresholdMetTrigger()))
                .thenReturn(Optional.of(3));

        service.processDeathSignal("creator-1", "INACTIVITY", "ref-003");

        verify(notifications, never()).notifyAdminThresholdMet(anyString(), anyString());
    }

    @Test
    void duplicateSourceInsertFails_catchesContinues_noThreshold() {
        when(db.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.of(pendingTrigger()))
                .thenReturn(Optional.of(1));
        // Simulate duplicate key violation on INSERT_SOURCE — 4 varargs
        org.mockito.Mockito.doThrow(new RuntimeException("duplicate key"))
                .when(db).execute(anyString(), any(), any(), any(), any());

        service.processDeathSignal("creator-1", "DEATH_REGISTRY", "ref-dup");

        verify(notifications, never()).notifyAdminThresholdMet(anyString(), anyString());
    }
}
