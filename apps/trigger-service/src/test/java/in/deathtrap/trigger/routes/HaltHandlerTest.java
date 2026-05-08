package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.config.JwtService;
import java.time.Instant;
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

/** Unit tests for HaltHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class HaltHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private HaltHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private HaltHandler.SessionRow session() {
        return new HaltHandler.SessionRow("sess-1", "creator-1", "trg-1");
    }

    @Test
    void validHalt_returns200() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(session()))
                .thenReturn((List) List.of("otp-1"));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.halt(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void noInitiatedSession_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.halt(BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void mfaNotVerified_throwsAuthSessionInvalid() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(session()))
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.halt(BEARER));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void nonCreator_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());

        AppException ex = assertThrows(AppException.class, () -> handler.halt(BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
