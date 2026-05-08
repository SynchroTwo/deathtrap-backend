package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for GetSessionStatusHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class GetSessionStatusHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;

    @InjectMocks private GetSessionStatusHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String SESSION_ID = "session-1";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoverySession initiatedSession(Instant lockedUntil) {
        return new RecoverySession(SESSION_ID, "creator-1", "trigger-1", "blob-1",
                "initiated", Instant.now(), lockedUntil, null, Instant.now());
    }

    private RecoverySession completedSession() {
        return new RecoverySession(SESSION_ID, "creator-1", "trigger-1", "blob-1",
                "completed", Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(3600), Instant.now(), Instant.now());
    }

    private RecoveryBlobLayer layer() {
        return new RecoveryBlobLayer("layer-1", "blob-1", 1,
                "nominee-1", "nominee", "pubkey-1", "a".repeat(64), Instant.now());
    }

    // SELECT_SESSION takes 1 vararg → 3 matchers
    // SELECT_AUTH_LAYER takes 2 varargs (blobId, partyId) → 4 matchers
    // SELECT_PEEL_EVENTS takes 1 vararg → 3 matchers
    // SELECT_LAYER_COUNT takes 1 vararg → 3 matchers
    // SELECT_NEXT_PARTY takes 2 varargs (blobId, layerOrder) → 4 matchers

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void initiatedSession_timelockActive_returnsTimelockTrue() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        Instant futurelock = Instant.now().plusSeconds(3600);
        when(dbClient.query(anyString(), any(), any()))        // 1-vararg: session, peels, layerCount
                .thenReturn((List) List.of(initiatedSession(futurelock)))  // session
                .thenReturn((List) Collections.emptyList())               // peel events
                .thenReturn((List) List.of(2));                           // layer count
        when(dbClient.query(anyString(), any(), any(), any())) // 2-vararg: next party
                .thenReturn((List) List.of(layer()));

        ResponseEntity<?> response = handler.getStatus(SESSION_ID, BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void initiatedSession_timelockExpired_autoAdvancesToInProgress() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        Instant pastlock = Instant.now().minusSeconds(1);
        RecoverySession advanced = new RecoverySession(SESSION_ID, "creator-1", "trigger-1",
                "blob-1", "in_progress", Instant.now().minusSeconds(7200),
                pastlock, null, Instant.now());
        when(dbClient.query(anyString(), any(), any()))        // 1-vararg
                .thenReturn((List) List.of(initiatedSession(pastlock)))    // first load
                .thenReturn((List) List.of(advanced))                      // reloaded after advance
                .thenReturn((List) Collections.emptyList())               // peel events
                .thenReturn((List) List.of(2));                           // layer count
        when(dbClient.query(anyString(), any(), any(), any())) // 2-vararg: next party
                .thenReturn((List) List.of(layer()));

        ResponseEntity<?> response = handler.getStatus(SESSION_ID, BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void callerNotInSession_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        Instant futurelock = Instant.now().plusSeconds(3600);
        when(dbClient.query(anyString(), any(), any()))        // 1-vararg: session
                .thenReturn((List) List.of(initiatedSession(futurelock)));
        when(dbClient.query(anyString(), any(), any(), any())) // 2-vararg: auth check → empty
                .thenReturn((List) Collections.emptyList());

        AppException ex = assertThrows(AppException.class,
                () -> handler.getStatus(SESSION_ID, BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void completedSession_returnsCompletedStatus() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))        // 1-vararg
                .thenReturn((List) List.of(completedSession()))           // session
                .thenReturn((List) Collections.emptyList())               // peel events
                .thenReturn((List) List.of(2));                           // layer count

        ResponseEntity<?> response = handler.getStatus(SESSION_ID, BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void sessionNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))        // 1-vararg: session not found
                .thenReturn(Collections.emptyList());

        AppException ex = assertThrows(AppException.class,
                () -> handler.getStatus(SESSION_ID, BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }
}
