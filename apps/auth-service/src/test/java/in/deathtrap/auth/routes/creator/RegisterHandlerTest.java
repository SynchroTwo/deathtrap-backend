package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.HibpClient;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for RegisterHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class RegisterHandlerTest {

    @Mock
    private DbClient dbClient;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuditWriter auditWriter;

    @Mock
    private HibpClient hibpClient;

    @InjectMocks
    private RegisterHandler handler;

    private static final String HIBP_PREFIX = "ABCDE";
    private static final String HIBP_SUFFIX = "A".repeat(35);

    private RegisterCreatorRequest validRequest() {
        return new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", "Test Address",
                "XXXX1234", "KYC-REF-001",
                HIBP_PREFIX, HIBP_SUFFIX, true, 80,
                "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAE\n-----END PUBLIC KEY-----",
                "abc123fingerprint",
                "encryptedPrivkeyBase64==", "nonceBase64==", "authTagBase64==",
                "a".repeat(64), 1, 12);
    }

    @Test
    void validRequest_createsUserAndReturns201() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.empty());
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.register(validRequest(), "Bearer valid-verified-token");

        assertEquals(201, response.getStatusCode().value());
        verify(auditWriter).write(any());
    }

    @Test
    void missingBearerToken_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.register(validRequest(), null));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void hibpFailed_throwsPassphraseCompromised() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        doThrow(AppException.passphraseCompromised())
                .when(hibpClient).checkPassphrase(anyString(), anyString(), anyBoolean());

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(validRequest(), "Bearer valid-token"));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void lowEntropy_throwsPassphraseCompromised() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        RegisterCreatorRequest bad = new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", "Test Address",
                "XXXX1234", "KYC-REF-001",
                HIBP_PREFIX, HIBP_SUFFIX, true, 40,
                "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----",
                "fp", "enc==", "nonce==", "tag==", "a".repeat(64), 1, 12);

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(bad, "Bearer valid-token"));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void duplicateMobile_throwsRegistrationDuplicate() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of("existing-user-id"));

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(validRequest(), "Bearer valid-token"));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void duplicateEmail_throwsRegistrationDuplicate() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        when(dbClient.queryOne(anyString(), any(), any()))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of("existing-user-id"));

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(validRequest(), "Bearer valid-token"));

        assertEquals(ErrorCode.AUTH_REGISTRATION_DUPLICATE, ex.getErrorCode());
    }

    @Test
    void invalidSaltHex_throwsValidationFailed() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        RegisterCreatorRequest bad = new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", "Test Address",
                "XXXX1234", "KYC-REF-001",
                HIBP_PREFIX, HIBP_SUFFIX, true, 80,
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
                "fp", "enc==", "nonce==", "tag==", "tooshort", 1, 12);

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(bad, "Bearer valid-token"));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void invalidInactivityMonths_throwsValidationFailed() {
        when(jwtService.validateVerifiedToken(anyString())).thenReturn("+919876543210");
        RegisterCreatorRequest bad = new RegisterCreatorRequest(
                "Test User", LocalDate.of(1990, 1, 1),
                "+919876543210", "test@example.com", "Test Address",
                "XXXX1234", "KYC-REF-001",
                HIBP_PREFIX, HIBP_SUFFIX, true, 80,
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
                "fp", "enc==", "nonce==", "tag==", "a".repeat(64), 1, 7);

        AppException ex = assertThrows(AppException.class,
                () -> handler.register(bad, "Bearer valid-token"));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }
}
