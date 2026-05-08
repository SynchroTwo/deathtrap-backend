package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.RegisterLawyerRequest;
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

/** Unit tests for RegisterLawyerHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class RegisterLawyerHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private RegisterLawyerHandler handler;

    private static final String VALID_HEX_64 = "b".repeat(64);
    private static final String VALID_PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----";

    private RegisterLawyerRequest validRequest() {
        return new RegisterLawyerRequest(
                "Adv. Rajan Mehta", "+919812345678", "rajan@lawfirm.com",
                "Bar Council of Maharashtra", "MH/12345/2010",
                VALID_HEX_64, VALID_PUBKEY, VALID_HEX_64,
                "encryptedBlob==", "nonce==", "authTag==");
    }

    @Test
    void validRequest_returnsPendingStatus() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(1L))  // OTP verified
                .thenReturn(List.of(0L))  // mobile unique
                .thenReturn(List.of(0L))  // email unique
                .thenReturn(List.of(0L)); // enrollment unique

        ResponseEntity<?> response = handler.registerLawyer(validRequest());

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void duplicateMobile_throwsRegistrationDuplicate() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(1L))  // OTP verified
                .thenReturn(List.of(1L)); // mobile exists

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerLawyer(validRequest()));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void duplicateEnrollmentNo_throwsRegistrationDuplicate() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(1L))  // OTP verified
                .thenReturn(List.of(0L))  // mobile unique
                .thenReturn(List.of(0L))  // email unique
                .thenReturn(List.of(1L)); // enrollment exists

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerLawyer(validRequest()));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void missingPublicKeyPem_throwsValidationFailed() {
        RegisterLawyerRequest badRequest = new RegisterLawyerRequest(
                "Adv. Rajan Mehta", "+919812345678", "rajan@lawfirm.com",
                "Bar Council of Maharashtra", "MH/12345/2010",
                VALID_HEX_64, "not-a-pem-key", VALID_HEX_64,
                "encryptedBlob==", "nonce==", "authTag==");

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerLawyer(badRequest));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void otpNotVerified_throwsSessionInvalid() {
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(0L));

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerLawyer(validRequest()));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }
}
