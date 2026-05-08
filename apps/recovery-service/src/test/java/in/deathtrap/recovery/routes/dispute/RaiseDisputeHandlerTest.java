package in.deathtrap.recovery.routes.dispute;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.RaiseDisputeRequest;
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

/** Unit tests for RaiseDisputeHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class RaiseDisputeHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private RaiseDisputeHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload unrelatedJwt() {
        return new JwtPayload("unrelated-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoverySession inProgressSession(String status) {
        return new RecoverySession("session-1", "creator-1", "trigger-1", "blob-1",
                status, Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(3600), null, Instant.now());
    }

    private RecoveryBlobLayer nomineeLayer() {
        return new RecoveryBlobLayer("layer-1", "blob-1", 1,
                "nominee-1", "nominee", "pubkey-1", "a".repeat(64), Instant.now());
    }

    private RaiseDisputeRequest req() {
        return new RaiseDisputeRequest("session-1", "I believe this is fraudulent");
    }

    // SELECT_SESSION (1 vararg) → 3 matchers
    // SELECT_AUTH_LAYER (2 varargs: blobId, partyId) → 4 matchers

    @Test
    void nomineeRaisesDispute_sessionBecomesDisputed_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: session
                .thenReturn((List) List.of(inProgressSession("in_progress")));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: auth layer
                .thenReturn((List) List.of(nomineeLayer()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.raiseDispute(req(), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void completedSession_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: session → completed
                .thenReturn((List) List.of(inProgressSession("completed")));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: auth layer
                .thenReturn((List) List.of(nomineeLayer()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.raiseDispute(req(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void alreadyDisputed_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: session → disputed
                .thenReturn((List) List.of(inProgressSession("disputed")));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: auth layer
                .thenReturn((List) List.of(nomineeLayer()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.raiseDispute(req(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void unrelatedParty_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(unrelatedJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: session
                .thenReturn((List) List.of(inProgressSession("in_progress")));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: auth layer → empty
                .thenReturn((List) Collections.emptyList());

        AppException ex = assertThrows(AppException.class,
                () -> handler.raiseDispute(req(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
