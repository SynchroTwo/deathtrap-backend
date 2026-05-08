package in.deathtrap.recovery.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for BlobRebuildLogService — no Spring context. */
@ExtendWith(MockitoExtension.class)
class BlobRebuildLogServiceTest {

    @Mock private DbClient db;

    @InjectMocks private BlobRebuildLogService service;

    @Test
    void successfulLog_dbExecuteCalled() {
        service.log("creator-1", "old-blob", "new-blob", "NOMINEE_ADDED", "creator-1", "creator");

        verify(db, times(1)).execute(anyString(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void dbExecuteThrows_noExceptionPropagated() {
        doThrow(AppException.internalError()).when(db).execute(anyString(), any(), any(), any(),
                any(), any(), any(), any());

        service.log("creator-1", null, "new-blob", "INITIAL_BUILD", "creator-1", "creator");
        // no exception thrown — method is non-throwing by design
    }
}
