package in.deathtrap.locker.routes.locker;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
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

/** Unit tests for InitLockerHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class InitLockerHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private InitLockerHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    @Test
    void validCreator_createsLockerAndAssets_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of()); // no existing locker
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.initLocker(BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void lockerAlreadyExists_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of("locker-already"));

        AppException ex = assertThrows(AppException.class, () -> handler.initLocker(BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void nonCreatorPartyType_throwsForbidden() {
        JwtPayload nomineeJwt = new JwtPayload("nominee-1", PartyType.NOMINEE, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt);

        AppException ex = assertThrows(AppException.class, () -> handler.initLocker(BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
