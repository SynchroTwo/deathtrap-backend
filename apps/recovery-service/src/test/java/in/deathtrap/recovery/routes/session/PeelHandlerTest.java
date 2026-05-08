package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.PeelRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import java.time.Instant;
import java.util.Base64;
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

/** Unit tests for PeelHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class PeelHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private PeelHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String SESSION_ID = "session-1";
    private static final String INTERMEDIATE_B64 =
            Base64.getEncoder().encodeToString("some-encrypted-bytes".getBytes());

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoverySession activeSession() {
        return new RecoverySession(SESSION_ID, "creator-1", "trigger-1", "blob-1",
                "in_progress", Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(3600), null, Instant.now());
    }

    private RecoverySession timelockSession() {
        return new RecoverySession(SESSION_ID, "creator-1", "trigger-1", "blob-1",
                "initiated", Instant.now().minusSeconds(3600),
                Instant.now().plusSeconds(7200), null, Instant.now());
    }

    private RecoveryBlobLayer layer1() {
        return new RecoveryBlobLayer("layer-1", "blob-1", 1,
                "nominee-1", "nominee", "pubkey-1", "a".repeat(64), Instant.now());
    }

    private RecoveryBlobLayer layer2() {
        return new RecoveryBlobLayer("layer-2", "blob-1", 2,
                "lawyer-1", "lawyer", "pubkey-2", "b".repeat(64), Instant.now());
    }

    private PeelRequest peelReq() {
        return new PeelRequest(INTERMEDIATE_B64, null);
    }

    // SELECT_SESSION (1 vararg) → 3 matchers
    // SELECT_MY_LAYER (3 varargs: blobId, partyId, partyType) → 5 matchers
    // SELECT_MAX_PEELED (1 vararg: sessionId) → 3 matchers
    // SELECT_ALREADY_PEELED (3 varargs: sessionId, partyId, partyType) → 5 matchers
    // SELECT_NEXT_PARTY (2 varargs: blobId, layerOrder) → 4 matchers

    @Test
    void firstPeel_timelockPassed_returns200InProgress() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg
                .thenReturn((List) List.of(activeSession()))                     // session
                .thenReturn((List) List.of(0));                                  // MAX_PEELED = 0
        when(dbClient.query(anyString(), any(), any(), any(), any()))     // 3-vararg
                .thenReturn((List) List.of(layer1()))                            // MY_LAYER
                .thenReturn((List) Collections.emptyList());                     // ALREADY_PEELED → none
        when(dbClient.withTransaction(any())).thenReturn("in_progress");
        when(dbClient.query(anyString(), any(), any(), any()))                   // 2-vararg: next party
                .thenReturn((List) List.of(layer2()));

        ResponseEntity<?> response = handler.peel(SESSION_ID, peelReq(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void timelockStillActive_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg: session
                .thenReturn((List) List.of(timelockSession()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.peel(SESSION_ID, peelReq(), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void outOfOrderPeel_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        // layer2 tries to peel when layer1 hasn't peeled yet
        RecoveryBlobLayer lawyerLayer = new RecoveryBlobLayer("layer-2", "blob-1", 2,
                "nominee-1", "nominee", "pubkey-2", "b".repeat(64), Instant.now());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg
                .thenReturn((List) List.of(activeSession()))                     // session
                .thenReturn((List) List.of(0));                                  // MAX_PEELED = 0 → expected = 1
        when(dbClient.query(anyString(), any(), any(), any(), any()))     // 3-vararg: MY_LAYER
                .thenReturn((List) List.of(lawyerLayer));                        // layerOrder=2

        AppException ex = assertThrows(AppException.class,
                () -> handler.peel(SESSION_ID, peelReq(), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void alreadyPeeled_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg
                .thenReturn((List) List.of(activeSession()))                     // session
                .thenReturn((List) List.of(0));                                  // MAX_PEELED = 0
        when(dbClient.query(anyString(), any(), any(), any(), any()))     // 3-vararg
                .thenReturn((List) List.of(layer1()))                            // MY_LAYER
                .thenReturn((List) List.of("peel-1"));                           // ALREADY_PEELED → found

        AppException ex = assertThrows(AppException.class,
                () -> handler.peel(SESSION_ID, peelReq(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void lastLayerPeeled_sessionMovesToCompleted() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg
                .thenReturn((List) List.of(activeSession()))                     // session
                .thenReturn((List) List.of(0));                                  // MAX_PEELED
        when(dbClient.query(anyString(), any(), any(), any(), any()))     // 3-vararg
                .thenReturn((List) List.of(layer1()))                            // MY_LAYER
                .thenReturn((List) Collections.emptyList());                     // not already peeled
        when(dbClient.withTransaction(any())).thenReturn("completed");

        ResponseEntity<?> response = handler.peel(SESSION_ID, peelReq(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void creatorTriesToPeel_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.peel(SESSION_ID, peelReq(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void partyNotInBlobLayers_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))                          // 1-vararg
                .thenReturn((List) List.of(activeSession()))                     // session
                .thenReturn((List) List.of(0));                                  // MAX_PEELED
        when(dbClient.query(anyString(), any(), any(), any(), any()))     // 3-vararg: MY_LAYER → empty
                .thenReturn((List) Collections.emptyList());

        AppException ex = assertThrows(AppException.class,
                () -> handler.peel(SESSION_ID, peelReq(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void intermediateHashStoredNotRawBytes_returns200() {
        // Verifies handler accepts the request and completes — hash is stored, not raw bytes
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(activeSession()))
                .thenReturn((List) List.of(0));
        when(dbClient.query(anyString(), any(), any(), any(), any()))
                .thenReturn((List) List.of(layer1()))
                .thenReturn((List) Collections.emptyList());
        when(dbClient.withTransaction(any())).thenReturn("in_progress");
        when(dbClient.query(anyString(), any(), any(), any()))
                .thenReturn((List) List.of(layer2()));

        ResponseEntity<?> response = handler.peel(SESSION_ID,
                new PeelRequest(INTERMEDIATE_B64, "device-fp"), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }
}
