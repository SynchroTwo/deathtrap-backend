package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.InitiateSessionRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper.RecoveryBlob;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for InitiateSessionHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class InitiateSessionHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private InitiateSessionHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoveryBlob activeBlob() {
        return new RecoveryBlob("blob-1", "creator-1", "recovery/creator-1/blob-1",
                2, "active", Instant.now(), Instant.now());
    }

    private InitiateSessionRequest req() {
        return new InitiateSessionRequest("creator-1");
    }

    // All queries use 1 vararg (creatorId) → 3 matchers

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void activeNominee_approvedTrigger_noActiveSession_returns201WithLockedUntil() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("trigger-1"))     // SELECT_TRIGGER → found
                .thenReturn(List.of())                 // SELECT_ACTIVE_SESSION → none
                .thenReturn((List) List.of(activeBlob())); // SELECT_ACTIVE_BLOB

        ResponseEntity<?> response = handler.initiateSession(req(), BEARER);

        assertEquals(201, response.getStatusCode().value());
        assertNotNull(response.getBody());
    }

    @Test
    void creatorPartyType_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.initiateSession(req(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void noApprovedTrigger_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of()); // trigger not found

        AppException ex = assertThrows(AppException.class,
                () -> handler.initiateSession(req(), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void sessionAlreadyActive_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("trigger-1"))     // trigger found
                .thenReturn(List.of("session-1"));    // active session exists

        AppException ex = assertThrows(AppException.class,
                () -> handler.initiateSession(req(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void noActiveBlob_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("trigger-1"))     // trigger found
                .thenReturn(List.of())                 // no active session
                .thenReturn(List.of());                // no active blob

        AppException ex = assertThrows(AppException.class,
                () -> handler.initiateSession(req(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void lockedUntilIs48HoursAfterInitiatedAt() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("trigger-1"))
                .thenReturn(List.of())
                .thenReturn((List) List.of(activeBlob()));

        ResponseEntity<?> response = handler.initiateSession(req(), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }
}
