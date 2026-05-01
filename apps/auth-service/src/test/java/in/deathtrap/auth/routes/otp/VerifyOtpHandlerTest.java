package in.deathtrap.auth.routes.otp;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for VerifyOtpHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class VerifyOtpHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private VerifyOtpHandler handler;

    private OtpLog validOtpLog(String otp, OtpChannel channel) {
        return new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                channel, OtpPurpose.LOGIN, Sha256Util.hashHex(otp),
                0, false, null,
                Instant.now().plusSeconds(600), Instant.now());
    }

    /** fetchOtp calls queryOne(sql, mapper, partyId, channel, purpose) = 5 args → 5 matchers. */
    private void stubOtpQuery(Optional<OtpLog> first, Optional<OtpLog> second) {
        doReturn(first).doReturn(second)
                .when(dbClient).queryOne(anyString(), any(), any(), any(), any());
    }

    private void stubOtpQuery(Optional<OtpLog> result) {
        doReturn(result)
                .when(dbClient).queryOne(anyString(), any(), any(), any(), any());
    }

    @Test
    void bothOtpsValid_returnsVerifiedToken() {
        String mobileOtp = "123456";
        String emailOtp = "654321";
        stubOtpQuery(
                Optional.of(validOtpLog(mobileOtp, OtpChannel.SMS)),
                Optional.of(validOtpLog(emailOtp, OtpChannel.EMAIL)));
        when(jwtService.issueVerifiedToken(anyString(), any())).thenReturn("verified-jwt");

        ResponseEntity<?> response = handler.verifyOtp(
                new VerifyOtpRequest("party-1", mobileOtp, emailOtp, OtpPurpose.LOGIN));

        assertEquals(200, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void wrongMobileOtp_throwsOtpInvalid() {
        stubOtpQuery(Optional.of(validOtpLog("123456", OtpChannel.SMS)));

        AppException ex = assertThrows(AppException.class,
                () -> handler.verifyOtp(
                        new VerifyOtpRequest("party-1", "000000", "654321", OtpPurpose.LOGIN)));

        assertEquals(ErrorCode.AUTH_OTP_INVALID, ex.getErrorCode());
    }

    @Test
    void thirdFailureLocksMobileOtp() {
        OtpLog otpWith2Attempts = new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                OtpChannel.SMS, OtpPurpose.LOGIN, Sha256Util.hashHex("654321"),
                2, false, null,
                Instant.now().plusSeconds(600), Instant.now());
        stubOtpQuery(Optional.of(otpWith2Attempts));

        AppException ex = assertThrows(AppException.class,
                () -> handler.verifyOtp(
                        new VerifyOtpRequest("party-1", "000000", "000000", OtpPurpose.LOGIN)));

        assertEquals(ErrorCode.AUTH_OTP_LOCKED, ex.getErrorCode());
    }

    @Test
    void expiredMobileOtp_throwsOtpExpired() {
        OtpLog expiredOtp = new OtpLog("otp-id-1", "party-1", PartyType.CREATOR,
                OtpChannel.SMS, OtpPurpose.LOGIN, Sha256Util.hashHex("123456"),
                0, false, null,
                Instant.now().minusSeconds(1), Instant.now().minusSeconds(700));
        stubOtpQuery(Optional.of(expiredOtp));

        AppException ex = assertThrows(AppException.class,
                () -> handler.verifyOtp(
                        new VerifyOtpRequest("party-1", "123456", "123456", OtpPurpose.LOGIN)));

        assertEquals(ErrorCode.AUTH_OTP_EXPIRED, ex.getErrorCode());
    }

    @Test
    void noOtpFoundForParty_throwsNotFound() {
        stubOtpQuery(Optional.empty());

        AppException ex = assertThrows(AppException.class,
                () -> handler.verifyOtp(
                        new VerifyOtpRequest("party-1", "123456", "123456", OtpPurpose.LOGIN)));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }
}
