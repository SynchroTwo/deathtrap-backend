package in.deathtrap.trigger.routes;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.config.JwtService;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper.InactivityCheck;
import in.deathtrap.trigger.rowmapper.TriggerEventRowMapper.TriggerEvent;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for GetStatusHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class GetStatusHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;

    @InjectMocks private GetStatusHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    @Test
    void noCheckAndNoTrigger_returns200WithNullFields() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of())
                .thenReturn(List.of());

        ResponseEntity<?> response = handler.getStatus(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void withActiveTrigger_returns200WithTriggerInfo() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        InactivityCheck check = new InactivityCheck(
                "chk-1", "creator-1", Instant.now().minusSeconds(3600),
                Instant.now().plusSeconds(86400), 0, false, Instant.now(), Instant.now());
        TriggerEvent trigger = new TriggerEvent(
                "trg-1", "creator-1", "pending_threshold", false, null, Instant.now());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(check))
                .thenReturn((List) List.of(trigger));
        when(dbClient.queryOne(anyString(), any(), any())).thenReturn(Optional.of(1));

        ResponseEntity<?> response = handler.getStatus(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void withInactivityCheck_noActiveTrigger_returns200() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        InactivityCheck check = new InactivityCheck(
                "chk-1", "creator-1", Instant.now().minusSeconds(3600),
                Instant.now().plusSeconds(86400), 1, false, Instant.now(), Instant.now());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn((List) List.of(check))
                .thenReturn(List.of());

        ResponseEntity<?> response = handler.getStatus(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }
}
