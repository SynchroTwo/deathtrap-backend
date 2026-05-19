package in.deathtrap.locker.routes.status;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for LockerStatusHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class LockerStatusHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;

    @InjectMocks private LockerStatusHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    @Test
    void validCreator_returnsStatusAndCompleteness() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenReturn(Optional.of(new LockerStatusHandler.LockerMetaRow("locker-1", 42)));
        when(dbClient.query(anyString(), any(), anyString()))
                .thenReturn(List.of(
                        new LockerStatusHandler.CategoryStatus("bank_accounts", "filled", 3, 1024L, Instant.now()),
                        new LockerStatusHandler.CategoryStatus("mutual_funds", "empty", 0, 0L, null)
                ));

        ResponseEntity<ApiResponse<LockerStatusHandler.LockerStatusResponse>> response = handler.status(BEARER);

        assertEquals(200, response.getStatusCode().value());
        LockerStatusHandler.LockerStatusResponse body = response.getBody().data();
        assertNotNull(body);
        assertEquals(42, body.completenessPct());
        assertEquals(2, body.categories().size());
        assertEquals("filled", body.categories().get(0).status());
        assertEquals(3, body.categories().get(0).version());
    }

    @Test
    void missingAuth_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class, () -> handler.status(null));
        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void nonCreatorParty_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());

        AppException ex = assertThrows(AppException.class, () -> handler.status(BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void noLockerForUser_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.queryOne(anyString(), any(), anyString())).thenReturn(Optional.empty());

        AppException ex = assertThrows(AppException.class, () -> handler.status(BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }
}
