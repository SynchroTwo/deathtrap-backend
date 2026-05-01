package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for LogoutHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class LogoutHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private LogoutHandler handler;

    private JwtPayload validPayload() {
        return new JwtPayload("user-1", PartyType.CREATOR, "session-jti-1",
                Instant.now().getEpochSecond(),
                Instant.now().plusSeconds(900).getEpochSecond());
    }

    @Test
    void validToken_revokesSessionAndInsertsRevokedToken() {
        when(jwtService.validateToken(anyString())).thenReturn(validPayload());
        when(dbClient.execute(anyString(), any())).thenReturn(1).thenReturn(1);

        ResponseEntity<?> response = handler.logout("Bearer valid.jwt.token");

        assertEquals(204, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void alreadyRevokedSession_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(validPayload());
        when(dbClient.execute(anyString(), any())).thenReturn(0);

        AppException ex = assertThrows(AppException.class,
                () -> handler.logout("Bearer valid.jwt.token"));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void missingBearerPrefix_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.logout("InvalidHeader"));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void nullAuthHeader_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.logout(null));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }
}
