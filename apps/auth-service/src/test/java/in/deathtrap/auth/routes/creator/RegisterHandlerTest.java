package in.deathtrap.auth.routes.creator;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.RegisterCreatorRequest;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for RegisterHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class RegisterHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private AuditWriter auditWriter;

    @InjectMocks
    private RegisterHandler handler;

    private RegisterCreatorRequest validRequest() {
        return new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null,
                "XXXX1234",
                "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAE\n-----END PUBLIC KEY-----",
                "encryptedPrivkeyBase64==", "nonceBase64==", "authTagBase64==",
                "a".repeat(64), 12);
    }

    @Test
    void validRequest_createsUserAndReturns201() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.empty());
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.register(validRequest());

        assertEquals(201, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void duplicateMobile_throwsRegistrationDuplicate() {
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of("existing-user-id"));

        AppException ex = assertThrows(AppException.class, () -> handler.register(validRequest()));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void duplicateEmail_throwsRegistrationDuplicate() {
        when(dbClient.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of("existing-user-id"));

        AppException ex = assertThrows(AppException.class, () -> handler.register(validRequest()));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void invalidSaltHex_throwsValidationFailed() {
        RegisterCreatorRequest badRequest = new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null,
                "XXXX1234",
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
                "enc==", "nonce==", "tag==",
                "tooshort", 12);

        AppException ex = assertThrows(AppException.class, () -> handler.register(badRequest));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void invalidInactivityMonths_throwsValidationFailed() {
        RegisterCreatorRequest badRequest = new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", null,
                "XXXX1234",
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
                "enc==", "nonce==", "tag==",
                "a".repeat(64), 7);

        AppException ex = assertThrows(AppException.class, () -> handler.register(badRequest));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }
}
