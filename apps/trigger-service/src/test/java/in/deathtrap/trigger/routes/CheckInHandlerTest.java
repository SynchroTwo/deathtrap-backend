package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.config.JwtService;
import in.deathtrap.trigger.service.TriggerEventService;
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

/** Unit tests for CheckInHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class CheckInHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private TriggerEventService triggerEventService;

    @InjectMocks private CheckInHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    @Test
    void activeCreator_checkIn_returns200WithNextCheckAt() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(new CheckInHandler.CreatorRow("creator-1", "active", 6)));

        ResponseEntity<?> response = handler.checkIn(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void checkIn_cancelsActiveTrigger_returns200() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(new CheckInHandler.CreatorRow("creator-1", "active", 6)));
        when(triggerEventService.haltPendingTriggers(anyString())).thenReturn(1);

        ResponseEntity<?> response = handler.checkIn(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void creatorNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.checkIn(BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void suspendedCreator_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(new CheckInHandler.CreatorRow("creator-1", "suspended", 6)));

        AppException ex = assertThrows(AppException.class, () -> handler.checkIn(BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
