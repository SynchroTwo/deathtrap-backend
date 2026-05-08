package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.Nominee;
import in.deathtrap.common.types.dto.RegisterNomineeRequest;
import in.deathtrap.common.types.enums.NomineeStatus;
import java.time.Instant;
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

/** Unit tests for RegisterNomineeHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class RegisterNomineeHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private BlobRebuildNotifier blobRebuildNotifier;

    @InjectMocks private RegisterNomineeHandler handler;

    private static final String VALID_HEX_64 = "a".repeat(64);
    private static final String VALID_PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----";

    private RegisterNomineeRequest validRequest() {
        return new RegisterNomineeRequest(
                VALID_HEX_64, VALID_HEX_64, VALID_PUBKEY, VALID_HEX_64,
                "encryptedBlob==", "nonce==", "authTag==", null, null);
    }

    private Nominee invitedNominee() {
        return new Nominee("nominee-1", "creator-1", "Alice", "+919876543210",
                "alice@example.com", "daughter", 1, "tokenHash",
                Instant.now().plusSeconds(86400), NomineeStatus.INVITED,
                false, null, Instant.now(), Instant.now());
    }

    @Test
    void validInviteToken_returnsAccessToken() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(invitedNominee()))
                .thenReturn(List.of(1L));
        when(jwtService.issueToken(anyString(), any(), anyString())).thenReturn("jwt-token");

        ResponseEntity<?> response = handler.registerNominee(validRequest());

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void invalidInviteToken_throwsInviteInvalid() {
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerNominee(validRequest()));

        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void expiredInviteToken_throwsInviteExpired() {
        Nominee expired = new Nominee("nominee-1", "creator-1", "Alice", "+919876543210",
                "alice@example.com", "daughter", 1, "tokenHash",
                Instant.now().minusSeconds(3600), NomineeStatus.INVITED,
                false, null, Instant.now(), Instant.now());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(expired));

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerNominee(validRequest()));

        assertEquals(ErrorCode.AUTH_INVITE_EXPIRED, ex.getErrorCode());
    }

    @Test
    void nomineeAlreadyRegistered_throwsConflict() {
        Nominee active = new Nominee("nominee-1", "creator-1", "Alice", "+919876543210",
                "alice@example.com", "daughter", 1, "tokenHash",
                Instant.now().plusSeconds(86400), NomineeStatus.ACTIVE,
                false, null, Instant.now(), Instant.now());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(active));

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerNominee(validRequest()));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void otpNotVerified_throwsSessionInvalid() {
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(invitedNominee()))
                .thenReturn(List.of(0L));

        AppException ex = assertThrows(AppException.class,
                () -> handler.registerNominee(validRequest()));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }
}
