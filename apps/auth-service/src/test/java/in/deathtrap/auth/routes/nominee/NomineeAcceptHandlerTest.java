package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.auth.service.InviteTokenTestFactory;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.AcceptInviteRequest;
import in.deathtrap.common.types.dto.AcceptInviteResponse;
import in.deathtrap.common.types.api.ApiResponse;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.support.TransactionCallback;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/** Unit tests for NomineeAcceptHandler (path A) — no Spring context. */
@ExtendWith(MockitoExtension.class)
class NomineeAcceptHandlerTest {

    private static final String CREATOR_ID = "creator-1";
    private static final String NOMINEE_ID = "nominee-1";

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private BlobRebuildNotifier blobRebuildNotifier;

    @InjectMocks private NomineeAcceptHandler handler;

    private KeyPair creatorKp;
    private String creatorPem;
    private String validToken;
    private String nomineePem;

    @BeforeEach
    void setUp() {
        creatorKp = InviteTokenTestFactory.generateEcKeyPair();
        creatorPem = InviteTokenTestFactory.spkiPem(creatorKp.getPublic());
        validToken = InviteTokenTestFactory.buildToken(creatorKp.getPrivate(),
                InviteTokenTestFactory.samplePayload(CREATOR_ID, NOMINEE_ID,
                        Instant.now().plusSeconds(86_400)));
        nomineePem = InviteTokenTestFactory.spkiPem(
                InviteTokenTestFactory.generateEcKeyPair().getPublic());
    }

    private AcceptInviteRequest request() {
        String saltB64 = Base64.getEncoder().encodeToString(new byte[32]);
        return new AcceptInviteRequest(validToken, nomineePem,
                "Y2lwaGVy", "bm9uY2U=", "dGFn", saltB64);
    }

    @Test
    @SuppressWarnings("unchecked")
    void accept_validToken_returns201WithSession() {
        when(dbClient.queryOne(anyString(), any(), any(Object[].class)))
                .thenReturn(Optional.of(creatorPem))
                .thenReturn(Optional.of("invited"));
        when(dbClient.execute(anyString(), any(Object[].class))).thenReturn(1);
        when(dbClient.withTransaction(any())).thenAnswer(inv ->
                inv.getArgument(0, TransactionCallback.class).doInTransaction(null));
        when(jwtService.getAccessTokenSeconds()).thenReturn(900L);
        when(jwtService.issueToken(anyString(), any(), anyString())).thenReturn("session-jwt");
        when(jwtService.issueRefreshToken(anyString(), any(), anyString())).thenReturn("refresh-jwt");

        ResponseEntity<ApiResponse<AcceptInviteResponse>> response = handler.accept(request());

        assertEquals(201, response.getStatusCode().value());
        AcceptInviteResponse body = response.getBody().data();
        assertEquals(NOMINEE_ID, body.nomineeId());
        assertEquals(CREATOR_ID, body.creatorId());
        assertEquals("nominee", body.partyType());
        assertEquals("session-jwt", body.sessionJwt());
        assertEquals("refresh-jwt", body.refreshToken());
    }

    @Test
    void accept_creatorPubkeyMissing_throwsInviteInvalid() {
        when(dbClient.queryOne(anyString(), any(), any(Object[].class))).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.accept(request()));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void accept_invalidSignature_throwsInviteInvalid() {
        String impostorPem = InviteTokenTestFactory.spkiPem(
                InviteTokenTestFactory.generateEcKeyPair().getPublic());
        when(dbClient.queryOne(anyString(), any(), any(Object[].class))).thenReturn(Optional.of(impostorPem));

        AppException ex = assertThrows(AppException.class, () -> handler.accept(request()));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void accept_nomineeNotFound_throwsNomineeNotFound() {
        when(dbClient.queryOne(anyString(), any(), any(Object[].class)))
                .thenReturn(Optional.of(creatorPem))
                .thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.accept(request()));
        assertEquals(ErrorCode.NOMINEE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void accept_alreadyRegistered_throwsAlreadyRegistered() {
        when(dbClient.queryOne(anyString(), any(), any(Object[].class)))
                .thenReturn(Optional.of(creatorPem))
                .thenReturn(Optional.of("active"));

        AppException ex = assertThrows(AppException.class, () -> handler.accept(request()));
        assertEquals(ErrorCode.NOMINEE_ALREADY_REGISTERED, ex.getErrorCode());
    }

    @Test
    void accept_invalidSaltB64_throwsValidationFailed() {
        AcceptInviteRequest bad = new AcceptInviteRequest(validToken, nomineePem,
                "Y2lwaGVy", "bm9uY2U=", "dGFn", "!!!not-base64!!!");

        AppException ex = assertThrows(AppException.class, () -> handler.accept(bad));
        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }
}
