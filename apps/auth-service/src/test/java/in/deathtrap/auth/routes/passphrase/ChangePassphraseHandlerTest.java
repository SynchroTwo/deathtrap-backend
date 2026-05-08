package in.deathtrap.auth.routes.passphrase;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.HibpClient;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.ChangePassphraseRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for ChangePassphraseHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class ChangePassphraseHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private BlobRebuildNotifier blobRebuildNotifier;
    @Mock private HibpClient hibpClient;

    @InjectMocks private ChangePassphraseHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String VALID_HEX_64 = "c".repeat(64);
    private static final String VALID_PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----";
    private static final String HIBP_PREFIX = "ABCDE";
    private static final String HIBP_SUFFIX = "B".repeat(35);

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-current",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "session-nominee",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private ChangePassphraseRequest validRequest() {
        return new ChangePassphraseRequest(VALID_PUBKEY, VALID_HEX_64, "encrypted==", "nonce==", "authTag==",
                HIBP_PREFIX, HIBP_SUFFIX, true);
    }

    @Test
    void validCreatorRequest_rotatesKeysAndReturns200() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(1L));

        ResponseEntity<?> response = handler.changePassphrase(validRequest(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void hibpCheckFalse_throwsPassphraseCompromised() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(1L));
        doThrow(AppException.passphraseCompromised())
                .when(hibpClient).checkPassphrase(anyString(), anyString(), anyBoolean());

        AppException ex = assertThrows(AppException.class,
                () -> handler.changePassphrase(validRequest(), BEARER));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void otpNotVerified_throwsSessionInvalid() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(0L));

        AppException ex = assertThrows(AppException.class,
                () -> handler.changePassphrase(validRequest(), BEARER));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void validNomineeRequest_resolvesBlobRebuild() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(1L))           // OTP verified
                .thenReturn(List.of("creator-1")); // nominee creator lookup

        handler.changePassphrase(validRequest(), BEARER);

        verify(blobRebuildNotifier).notifyRebuildRequired(
                anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void sqsNotConfigured_passphraseChangeSucceeds() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(1L));

        ResponseEntity<?> response = handler.changePassphrase(validRequest(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }
}
