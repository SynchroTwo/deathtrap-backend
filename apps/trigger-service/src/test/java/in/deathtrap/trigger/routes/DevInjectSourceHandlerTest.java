package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.trigger.routes.DevInjectSourceHandler.DevInjectSourceRequest;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for the B-A6-4 dev source-injection endpoint. */
@ExtendWith(MockitoExtension.class)
class DevInjectSourceHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private DevInjectSourceHandler handler;

    private DevInjectSourceRequest req() {
        return new DevInjectSourceRequest("+919999999999", "death_registry");
    }

    @Test
    void prodEnvironment_returns404AndTouchesNoDb() {
        ReflectionTestUtils.setField(handler, "environment", "prod");

        AppException ex = assertThrows(AppException.class, () -> handler.inject(req()));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
        verify(dbClient, never()).execute(anyString(), any(Object[].class));
    }

    @Test
    void invalidSourceType_throwsValidationFailed() {
        ReflectionTestUtils.setField(handler, "environment", "staging");

        AppException ex = assertThrows(AppException.class,
                () -> handler.inject(new DevInjectSourceRequest("+919999999999", "bogus")));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void secondDistinctSource_promotesTriggerToApproved() {
        ReflectionTestUtils.setField(handler, "environment", "staging");
        when(dbClient.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.of("creator-1"))   // SELECT_USER_BY_MOBILE
                .thenReturn(Optional.empty())            // SELECT_ACTIVE_TRIGGER → create new
                .thenReturn(Optional.of(2));             // SELECT_VERIFIED_COUNT → threshold

        ResponseEntity<?> response = handler.inject(req());

        assertEquals(200, response.getStatusCode().value());
        verify(dbClient).execute(
                argThat(sql -> sql != null && sql.contains("status = 'approved'")
                        && sql.contains("threshold_met = TRUE")),
                any(Object[].class));
    }

    @Test
    void belowThreshold_doesNotPromote() {
        ReflectionTestUtils.setField(handler, "environment", "staging");
        when(dbClient.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.of("creator-1"))   // user
                .thenReturn(Optional.empty())            // new trigger
                .thenReturn(Optional.of(1));             // only 1 source so far

        ResponseEntity<?> response = handler.inject(req());

        assertEquals(200, response.getStatusCode().value());
        verify(dbClient, never()).execute(
                argThat(sql -> sql != null && sql.contains("status = 'approved'")),
                any(Object[].class));
    }
}
