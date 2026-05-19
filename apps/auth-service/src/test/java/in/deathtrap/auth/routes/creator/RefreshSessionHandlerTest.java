package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.RefreshSessionRequest;
import in.deathtrap.common.types.dto.RefreshSessionResponse;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
import java.util.Optional;
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

/** Unit tests for RefreshSessionHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class RefreshSessionHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private RefreshSessionHandler handler;

    private static final String SESSION_ID = "01HJEXAMPLE0000000000000XX";

    private JwtPayload payload() {
        long now = Instant.now().getEpochSecond();
        return new JwtPayload("user-1", PartyType.CREATOR, SESSION_ID, now, now + 604800);
    }

    private RefreshSessionRequest req() {
        return new RefreshSessionRequest("refresh.jwt.value");
    }

    private RefreshSessionHandler.SessionRow activeSessionRow() {
        return new RefreshSessionHandler.SessionRow(SESSION_ID, null, Instant.now().plusSeconds(86400));
    }

    @Test
    void validRefresh_returnsFreshTokens() {
        when(jwtService.validateRefreshToken(anyString())).thenReturn(payload());
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of(activeSessionRow()))   // session lookup
                .thenReturn(Optional.empty());                  // revoked_tokens lookup
        when(jwtService.issueToken(anyString(), any(PartyType.class), anyString())).thenReturn("new-session-jwt");
        when(jwtService.issueRefreshToken(anyString(), any(PartyType.class), anyString())).thenReturn("new-refresh-jwt");
        when(jwtService.getAccessTokenSeconds()).thenReturn(900L);

        ResponseEntity<ApiResponse<RefreshSessionResponse>> response = handler.refresh(req());

        assertEquals(200, response.getStatusCode().value());
        RefreshSessionResponse body = response.getBody().data();
        assertNotNull(body);
        assertEquals("new-session-jwt", body.sessionJwt());
        assertEquals("new-refresh-jwt", body.refreshToken());
    }

    @Test
    void invalidRefreshToken_throwsInvalidVerifiedToken() {
        when(jwtService.validateRefreshToken(anyString()))
                .thenThrow(AppException.invalidVerifiedToken());

        AppException ex = assertThrows(AppException.class, () -> handler.refresh(req()));

        assertEquals(ErrorCode.AUTH_INVALID_VERIFIED_TOKEN, ex.getErrorCode());
    }

    @Test
    void sessionRowMissing_throwsNotFound() {
        when(jwtService.validateRefreshToken(anyString())).thenReturn(payload());
        when(dbClient.queryOne(anyString(), any(), anyString())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.refresh(req()));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void sessionRevoked_throwsSessionRevoked() {
        RefreshSessionHandler.SessionRow revoked = new RefreshSessionHandler.SessionRow(
                SESSION_ID, Instant.now().minusSeconds(60), Instant.now().plusSeconds(86400));
        when(jwtService.validateRefreshToken(anyString())).thenReturn(payload());
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of(revoked));

        AppException ex = assertThrows(AppException.class, () -> handler.refresh(req()));

        assertEquals(ErrorCode.AUTH_SESSION_REVOKED, ex.getErrorCode());
    }

    @Test
    void jtiInRevokedTokens_throwsSessionRevoked() {
        when(jwtService.validateRefreshToken(anyString())).thenReturn(payload());
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of(activeSessionRow()))   // session lookup OK
                .thenReturn(Optional.of(SESSION_ID));           // revoked_tokens hit

        AppException ex = assertThrows(AppException.class, () -> handler.refresh(req()));

        assertEquals(ErrorCode.AUTH_SESSION_REVOKED, ex.getErrorCode());
    }

    @Test
    void sessionExpired_throwsSessionExpired() {
        RefreshSessionHandler.SessionRow expired = new RefreshSessionHandler.SessionRow(
                SESSION_ID, null, Instant.now().minusSeconds(60));
        when(jwtService.validateRefreshToken(anyString())).thenReturn(payload());
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of(expired))
                .thenReturn(Optional.empty());                  // revoked_tokens lookup

        AppException ex = assertThrows(AppException.class, () -> handler.refresh(req()));

        assertEquals(ErrorCode.AUTH_SESSION_EXPIRED, ex.getErrorCode());
    }
}
