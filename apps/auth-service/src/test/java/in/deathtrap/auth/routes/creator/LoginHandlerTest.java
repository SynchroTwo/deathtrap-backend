package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.LoginRequest;
import in.deathtrap.common.types.dto.LoginResponse;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.common.types.enums.UserStatus;
import java.time.Instant;
import java.time.LocalDate;
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

/** Unit tests for LoginHandler — no Spring context.
 *  Tests reflect the post-OTP-split contract: token in Authorization header,
 *  OTP already verified in DB before /auth/session is called. */
@ExtendWith(MockitoExtension.class)
class LoginHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private LoginHandler handler;

    private static final String VALID_TOKEN = "Bearer eyJ.valid.token";

    private User activeUser() {
        return new User("user-1", "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null, null,
                KycStatus.VERIFIED, UserStatus.ACTIVE,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
    }

    private LoginRequest validRequest() {
        return new LoginRequest("+919876543210", null, null);
    }

    @Test
    void validLogin_returnsTokensAndCryptoMaterial() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        // 4 sequential queryOne calls: OTP, user, salt, privkey blob
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of("otp-id-1"))
                .thenReturn(Optional.of(activeUser()))
                .thenReturn(Optional.of("a".repeat(64)))
                .thenReturn(Optional.of(new LoginHandler.PrivkeyBlob("ct==", "n==", "tg==")));
        when(jwtService.issueToken(anyString(), any(PartyType.class), anyString())).thenReturn("session-jwt");
        when(jwtService.issueRefreshToken(anyString(), any(PartyType.class), anyString())).thenReturn("refresh-jwt");
        when(jwtService.getAccessTokenSeconds()).thenReturn(900L);

        ResponseEntity<ApiResponse<LoginResponse>> response = handler.login(validRequest(), VALID_TOKEN);

        assertEquals(200, response.getStatusCode().value());
        LoginResponse body = response.getBody().data();
        assertNotNull(body);
        assertEquals("user-1", body.userId());
        assertEquals("creator", body.partyType());
        assertEquals("session-jwt", body.sessionJwt());
        assertEquals("refresh-jwt", body.refreshToken());
        assertEquals("a".repeat(64), body.saltHex());
        assertEquals("ct==", body.encryptedPrivkeyB64());
        assertEquals("n==", body.encryptedPrivkeyNonceB64());
        assertEquals("tg==", body.encryptedPrivkeyTagB64());
    }

    @Test
    void missingAuthorizationHeader_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.login(validRequest(), null));
        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void noVerifiedLoginOtp_throwsUnauthorized() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), anyString())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class,
                () -> handler.login(validRequest(), VALID_TOKEN));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void mobileNotFound_throwsNotFound() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of("otp-id-1"))
                .thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class,
                () -> handler.login(validRequest(), VALID_TOKEN));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void userStatusSuspended_throwsForbidden() {
        User suspended = new User("user-1", "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null, null,
                KycStatus.VERIFIED, UserStatus.SUSPENDED,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of("otp-id-1"))
                .thenReturn(Optional.of(suspended));

        AppException ex = assertThrows(AppException.class,
                () -> handler.login(validRequest(), VALID_TOKEN));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
