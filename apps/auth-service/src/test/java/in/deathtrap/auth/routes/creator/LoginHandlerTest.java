package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.LoginRequest;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.OtpPurpose;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for LoginHandler — no Spring context. */
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

    private User activeUser() {
        return new User("user-1", "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null, null, null,
                KycStatus.VERIFIED, UserStatus.ACTIVE,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
    }

    private LoginRequest validRequest() {
        return new LoginRequest("+919876543210", OtpPurpose.LOGIN, "valid-otp-token");
    }

    @Test
    void validLogin_returnsAccessTokenAndSessionId() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), anyString(), any(Instant.class)))
                .thenReturn(Optional.of("otp-id-1"));
        when(jwtService.issueToken(anyString(), any(PartyType.class), anyString())).thenReturn("jwt-token");

        ResponseEntity<?> response = handler.login(validRequest());

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void mobileNotFound_throwsNotFound() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.login(validRequest()));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void userStatusSuspended_throwsForbidden() {
        User suspended = new User("user-1", "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null, null, null,
                KycStatus.VERIFIED, UserStatus.SUSPENDED,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(suspended));

        AppException ex = assertThrows(AppException.class, () -> handler.login(validRequest()));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void otpTokenExpired_throwsSessionInvalid() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), anyString(), any(Instant.class)))
                .thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.login(validRequest()));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void otpTokenOlderThan5Min_throwsSessionInvalid() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), anyString(), any(Instant.class)))
                .thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.login(validRequest()));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }
}
