package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.OtpLog;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.LoginRequest;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.OtpChannel;
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

    private static final String MOBILE_OTP = "482931";
    private static final String EMAIL_OTP = "719203";

    private User activeUser() {
        return new User("user-1", "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null, null, null,
                KycStatus.VERIFIED, UserStatus.ACTIVE,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
    }

    private OtpLog validOtpLog(String otp, OtpChannel channel) {
        return new OtpLog("otp-id-1", "+919876543210", PartyType.CREATOR,
                channel, OtpPurpose.LOGIN, Sha256Util.hashHex(otp),
                0, false, null,
                Instant.now().plusSeconds(600), Instant.now());
    }

    private LoginRequest validRequest() {
        return new LoginRequest("+919876543210", MOBILE_OTP, EMAIL_OTP, null, null);
    }

    @Test
    void validLogin_returnsAccessTokenAndSessionId() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), any(), any()))
                .thenReturn(Optional.of(validOtpLog(MOBILE_OTP, OtpChannel.SMS)))
                .thenReturn(Optional.of(validOtpLog(EMAIL_OTP, OtpChannel.EMAIL)));
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
    void mobileOtpNotFound_throwsNotFound() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.login(validRequest()));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void wrongMobileOtp_throwsOtpInvalid() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(activeUser()));
        when(dbClient.queryOne(anyString(), any(), any(), any()))
                .thenReturn(Optional.of(validOtpLog("999999", OtpChannel.SMS)));

        AppException ex = assertThrows(AppException.class,
                () -> handler.login(new LoginRequest("+919876543210", "000000", EMAIL_OTP, null, null)));

        assertEquals(ErrorCode.AUTH_OTP_INVALID, ex.getErrorCode());
    }
}
