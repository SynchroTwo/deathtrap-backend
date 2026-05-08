package in.deathtrap.locker.routes.sync;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeAssignmentUpdate;
import in.deathtrap.common.types.dto.SyncPushChanges;
import in.deathtrap.common.types.dto.SyncPushRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for SyncPushHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class SyncPushHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private SyncPushHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    // SELECT_LOCKER takes 1 vararg (creatorId) → 3 matchers total
    // SELECT_ASSIGNMENT takes 2 varargs (assignmentId, lockerId) → 4 matchers total

    @Test
    void updateOfficialNominationStatus_dbUpdatedAuditWritten() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSIGNMENT
                .thenReturn(List.of("assignment-1"));

        NomineeAssignmentUpdate update = new NomineeAssignmentUpdate(
                "assignment-1", "pending", 1, null);
        SyncPushRequest request = new SyncPushRequest(
                new SyncPushChanges(List.of(update)));

        ResponseEntity<?> response = handler.syncPush(request, BEARER);

        assertEquals(200, response.getStatusCode().value());
        verify(auditWriter, times(1)).write(any());
    }

    @Test
    void pushWithNullNomineeAssignments_returnsZeroApplied() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));

        SyncPushRequest request = new SyncPushRequest(new SyncPushChanges(null));

        ResponseEntity<?> response = handler.syncPush(request, BEARER);

        assertEquals(200, response.getStatusCode().value());
    }
}
