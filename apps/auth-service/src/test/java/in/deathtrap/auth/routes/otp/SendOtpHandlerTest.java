package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.dto.SendOtpRequest;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import java.time.Instant;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for SendOtpHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class SendOtpHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private SendOtpHandler handler;

    @Test
    void validMobileSmsChannel_returns200WithExpiresIn() {
        SendOtpRequest request = new SendOtpRequest("+919876543210", null, OtpChannel.SMS, OtpPurpose.REGISTRATION);
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.empty());

        ResponseEntity<?> response = handler.sendOtp(request);

        assertEquals(200, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void validEmailChannel_returns200() {
        SendOtpRequest request = new SendOtpRequest(null, "user@example.com", OtpChannel.EMAIL, OtpPurpose.REGISTRATION);
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.empty());

        ResponseEntity<?> response = handler.sendOtp(request);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void bothMobileAndEmailNull_throwsValidationError() {
        SendOtpRequest request = new SendOtpRequest(null, null, OtpChannel.SMS, OtpPurpose.REGISTRATION);

        AppException ex = assertThrows(AppException.class, () -> handler.sendOtp(request));

        assertEquals(in.deathtrap.common.errors.ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void invalidMobileFormat_throwsValidationError() {
        SendOtpRequest request = new SendOtpRequest("12345", null, OtpChannel.SMS, OtpPurpose.REGISTRATION);

        AppException ex = assertThrows(AppException.class, () -> handler.sendOtp(request));

        assertEquals(in.deathtrap.common.errors.ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void partyHasLockedOtp_throwsOtpLocked() {
        SendOtpRequest request = new SendOtpRequest("+919876543210", null, OtpChannel.SMS, OtpPurpose.REGISTRATION);
        Instant futurelock = Instant.now().plusSeconds(1800);
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(futurelock));

        AppException ex = assertThrows(AppException.class, () -> handler.sendOtp(request));

        assertEquals(in.deathtrap.common.errors.ErrorCode.AUTH_OTP_LOCKED, ex.getErrorCode());
    }
}
