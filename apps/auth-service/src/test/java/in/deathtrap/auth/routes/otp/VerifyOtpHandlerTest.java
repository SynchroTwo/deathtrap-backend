package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.OtpLog;
import in.deathtrap.common.types.dto.VerifyOtpRequest;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for VerifyOtpHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class VerifyOtpHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private VerifyOtpHandler handler;

    private static final BCryptPasswordEncoder BCRYPT = new BCryptPasswordEncoder();

    private OtpLog validOtpLog(String otp) {
        return new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                OtpChannel.SMS, OtpPurpose.LOGIN, BCRYPT.encode(otp),
                0, false, null,
                Instant.now().plusSeconds(600), Instant.now());
    }

    @Test
    void validOtp_returnsVerifiedTrue() {
        String rawOtp = "123456";
        VerifyOtpRequest request = new VerifyOtpRequest("party-1", OtpPurpose.LOGIN, rawOtp);
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(validOtpLog(rawOtp)));
        when(dbClient.execute(anyString(), any())).thenReturn(1);

        ResponseEntity<?> response = handler.verifyOtp(request);

        assertEquals(200, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void wrongOtpFirstAttempt_incrementsAttemptsAndThrows400() {
        VerifyOtpRequest request = new VerifyOtpRequest("party-1", OtpPurpose.LOGIN, "000000");
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(validOtpLog("654321")));
        when(dbClient.execute(anyString(), any())).thenReturn(1);

        AppException ex = assertThrows(AppException.class, () -> handler.verifyOtp(request));

        assertEquals(ErrorCode.AUTH_OTP_INVALID, ex.getErrorCode());
        verify(dbClient).execute(anyString(), any());
    }

    @Test
    void wrongOtpThirdAttempt_setsLockedAndThrowsOtpLocked() {
        OtpLog otpWith2Attempts = new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                OtpChannel.SMS, OtpPurpose.LOGIN, BCRYPT.encode("654321"),
                2, false, null,
                Instant.now().plusSeconds(600), Instant.now());
        VerifyOtpRequest request = new VerifyOtpRequest("party-1", OtpPurpose.LOGIN, "000000");
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(otpWith2Attempts));

        AppException ex = assertThrows(AppException.class, () -> handler.verifyOtp(request));

        assertEquals(ErrorCode.AUTH_OTP_LOCKED, ex.getErrorCode());
    }

    @Test
    void expiredOtp_throwsOtpExpired() {
        OtpLog expiredOtp = new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                OtpChannel.SMS, OtpPurpose.LOGIN, BCRYPT.encode("123456"),
                0, false, null,
                Instant.now().minusSeconds(1), Instant.now().minusSeconds(700));
        VerifyOtpRequest request = new VerifyOtpRequest("party-1", OtpPurpose.LOGIN, "123456");
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(expiredOtp));

        AppException ex = assertThrows(AppException.class, () -> handler.verifyOtp(request));

        assertEquals(ErrorCode.AUTH_OTP_EXPIRED, ex.getErrorCode());
    }

    @Test
    void noOtpFoundForParty_throwsNotFound() {
        VerifyOtpRequest request = new VerifyOtpRequest("party-1", OtpPurpose.LOGIN, "123456");
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.verifyOtp(request));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }
}
