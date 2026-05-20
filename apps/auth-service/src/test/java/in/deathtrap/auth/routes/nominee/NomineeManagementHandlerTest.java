package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.CreateNomineeRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeView;
import in.deathtrap.common.types.dto.PubkeyView;
import in.deathtrap.common.types.dto.UpdateNomineeRequest;
import in.deathtrap.common.types.enums.PartyType;
import java.util.List;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/** Unit tests for NomineeManagementHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class NomineeManagementHandlerTest {

    private static final String CREATOR_BEARER = "Bearer creator-jwt";
    private static final String CREATOR_ID = "creator-1";

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private NomineeManagementHandler handler;

    private void asCreator() {
        when(jwtService.validateToken("creator-jwt"))
                .thenReturn(new JwtPayload(CREATOR_ID, PartyType.CREATOR, "jti", 0L, 0L));
    }

    private CreateNomineeRequest createReq() {
        return new CreateNomineeRequest("Bob", "bob@example.com", null, null);
    }

    @Test
    void create_returns201WithInvitedView() {
        asCreator();
        when(dbClient.execute(anyString(), any(Object[].class))).thenReturn(1);

        ResponseEntity<?> response = handler.create(createReq(), CREATOR_BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void create_missingBearer_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class, () -> handler.create(createReq(), null));
        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void create_nomineeJwt_throwsForbidden() {
        when(jwtService.validateToken("nominee-jwt"))
                .thenReturn(new JwtPayload("nominee-1", PartyType.NOMINEE, "jti", 0L, 0L));

        AppException ex = assertThrows(AppException.class,
                () -> handler.create(createReq(), "Bearer nominee-jwt"));
        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void list_returnsNominees() {
        asCreator();
        when(dbClient.query(anyString(), any(), any(Object[].class)))
                .thenReturn(List.of(new NomineeView("n1", CREATOR_ID, "Bob", "bob@example.com",
                        null, "invited", null, null, "2026-01-01T00:00:00Z", null, null)));

        ResponseEntity<?> response = handler.list(CREATOR_BEARER);
        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void update_noRowsAffected_throwsNomineeNotFound() {
        asCreator();
        when(dbClient.execute(anyString(), any(Object[].class))).thenReturn(0);

        AppException ex = assertThrows(AppException.class, () -> handler.update(
                "missing", new UpdateNomineeRequest("New", null, null), CREATOR_BEARER));
        assertEquals(ErrorCode.NOMINEE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void remove_noRowsAffected_throwsNomineeNotFound() {
        asCreator();
        when(dbClient.execute(anyString(), any(Object[].class))).thenReturn(0);

        AppException ex = assertThrows(AppException.class,
                () -> handler.remove("missing", CREATOR_BEARER));
        assertEquals(ErrorCode.NOMINEE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void remove_returns204() {
        asCreator();
        when(dbClient.execute(anyString(), any(Object[].class))).thenReturn(1);

        ResponseEntity<?> response = handler.remove("n1", CREATOR_BEARER);
        assertEquals(204, response.getStatusCode().value());
    }

    @Test
    void pubkey_notRegistered_throwsNomineeNotFound() {
        asCreator();
        lenient().when(dbClient.queryOne(anyString(), any(), any(Object[].class)))
                .thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class,
                () -> handler.pubkey("n1", CREATOR_BEARER));
        assertEquals(ErrorCode.NOMINEE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void pubkey_registered_returnsPubkey() {
        asCreator();
        when(dbClient.queryOne(anyString(), any(), any(Object[].class)))
                .thenReturn(Optional.of(new PubkeyView("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", "ff".repeat(32))));

        ResponseEntity<?> response = handler.pubkey("n1", CREATOR_BEARER);
        assertEquals(200, response.getStatusCode().value());
    }
}
