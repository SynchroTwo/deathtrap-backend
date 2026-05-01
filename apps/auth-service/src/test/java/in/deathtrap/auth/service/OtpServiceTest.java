package in.deathtrap.auth.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for OtpService — no Spring context. */
@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock
    private DbClient dbClient;

    @InjectMocks
    private OtpService otpService;

    @Test
    void generateAndStore_returns6DigitNumericOtp() {
        String otp = otpService.generateAndStore("party-1", OtpChannel.SMS, OtpPurpose.REGISTRATION);

        assertNotNull(otp);
        assertEquals(6, otp.length());
        assertTrue(otp.matches("\\d{6}"));
        // execute(sql, otpId, partyId, channel, purpose, otpHash, expiresAt, now) = 7 varargs → 8 matchers
        verify(dbClient).execute(anyString(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void checkRateLimit_underLimit_doesNotThrow() {
        // queryOne(sql, mapper, partyId, purpose) = 2 varargs → 4 matchers
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(2));

        otpService.checkRateLimit("party-1", OtpPurpose.REGISTRATION);
    }

    @Test
    void checkRateLimit_atLimit_throwsRateLimited() {
        // queryOne(sql, mapper, partyId, purpose) = 2 varargs → 4 matchers
        when(dbClient.queryOne(anyString(), any(), any(), any())).thenReturn(Optional.of(3));

        AppException ex = assertThrows(AppException.class,
                () -> otpService.checkRateLimit("party-1", OtpPurpose.REGISTRATION));

        assertEquals(ErrorCode.RATE_LIMITED, ex.getErrorCode());
    }

    @Test
    void getActiveOtpExpiry_returnsExpiry_whenExists() {
        Instant future = Instant.now().plusSeconds(300);
        // queryOne(sql, mapper, partyId, channel, purpose) = 3 varargs → 5 matchers
        when(dbClient.queryOne(anyString(), any(), any(), any(), any())).thenReturn(Optional.of(future));

        Optional<Instant> result = otpService.getActiveOtpExpiry("party-1", OtpChannel.SMS, OtpPurpose.REGISTRATION);

        assertTrue(result.isPresent());
        assertEquals(future, result.get());
    }

    @Test
    void verify_withCorrectOtp_marksVerified() throws Exception {
        String otp = "482931";
        stubVerifyQuery(sha256Hex(otp), 0, null, Instant.now().plusSeconds(600));

        otpService.verify("party-1", otp, OtpChannel.SMS, OtpPurpose.LOGIN);

        verify(dbClient).execute(anyString(), any());
    }

    @Test
    void verify_withExpiredOtp_throwsOtpExpired() throws Exception {
        stubVerifyQuery(sha256Hex("482931"), 0, null, Instant.now().minusSeconds(1));

        AppException ex = assertThrows(AppException.class,
                () -> otpService.verify("party-1", "482931", OtpChannel.SMS, OtpPurpose.LOGIN));

        assertEquals(ErrorCode.AUTH_OTP_EXPIRED, ex.getErrorCode());
    }

    @Test
    void verify_withLockedOtp_throwsOtpLocked() throws Exception {
        Instant lockedUntil = Instant.now().plusSeconds(1800);
        stubVerifyQuery(sha256Hex("482931"), 3, lockedUntil, Instant.now().plusSeconds(600));

        AppException ex = assertThrows(AppException.class,
                () -> otpService.verify("party-1", "482931", OtpChannel.SMS, OtpPurpose.LOGIN));

        assertEquals(ErrorCode.AUTH_OTP_LOCKED, ex.getErrorCode());
    }

    @Test
    void verify_withWrongOtp_throwsOtpInvalid() throws Exception {
        stubVerifyQuery(sha256Hex("482931"), 0, null, Instant.now().plusSeconds(600));

        AppException ex = assertThrows(AppException.class,
                () -> otpService.verify("party-1", "000000", OtpChannel.SMS, OtpPurpose.LOGIN));

        assertEquals(ErrorCode.AUTH_OTP_INVALID, ex.getErrorCode());
    }

    @Test
    void verify_thirdFailure_throwsOtpLocked() throws Exception {
        stubVerifyQuery(sha256Hex("482931"), 2, null, Instant.now().plusSeconds(600));

        AppException ex = assertThrows(AppException.class,
                () -> otpService.verify("party-1", "000000", OtpChannel.SMS, OtpPurpose.LOGIN));

        assertEquals(ErrorCode.AUTH_OTP_LOCKED, ex.getErrorCode());
    }

    /**
     * Uses doAnswer to invoke the real RowMapper with a mock ResultSet, constructing
     * the private OtpRecord inside OtpService and avoiding ClassCastException.
     * queryOne(sql, mapper, partyId, channel, purpose) = 3 varargs → 5 matchers.
     */
    @SuppressWarnings("unchecked")
    private void stubVerifyQuery(String otpHash, int attempts, Instant lockedUntil, Instant expiresAt)
            throws Exception {
        when(dbClient.queryOne(anyString(), any(), any(), any(), any()))
                .thenAnswer(inv -> {
                    RowMapper<Object> mapper = inv.getArgument(1);
                    ResultSet rs = mock(ResultSet.class);
                    when(rs.getString("otp_id")).thenReturn("otp-1");
                    when(rs.getString("otp_hash")).thenReturn(otpHash);
                    when(rs.getInt("attempts")).thenReturn(attempts);
                    when(rs.getTimestamp("locked_until")).thenReturn(
                            lockedUntil != null ? Timestamp.from(lockedUntil) : null);
                    when(rs.getTimestamp("expires_at")).thenReturn(Timestamp.from(expiresAt));
                    return Optional.of(mapper.mapRow(rs, 0));
                });
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
