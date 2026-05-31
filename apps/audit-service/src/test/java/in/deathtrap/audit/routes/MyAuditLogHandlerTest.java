package in.deathtrap.audit.routes;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.audit.config.JwtService;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.AuditQueryService;
import in.deathtrap.audit.service.AuditQueryService.AuditQueryResult;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for MyAuditLogHandler (GET /audit/me) — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class MyAuditLogHandlerTest {

    @Mock private AuditQueryService auditQueryService;
    @Mock private JwtService jwtService;

    private MyAuditLogHandler handler;

    private static final String BEARER = "Bearer party-jwt";
    private static final Instant NOW = Instant.parse("2026-05-08T10:00:00.000000Z");

    /** Row carrying a non-null ipAddress, to prove the handler omits it. */
    private static AuditLogRow rowWithIp(String id) {
        return new AuditLogRow(id, "RECOVERY_SESSION_INITIATED", "creator-1", "CREATOR",
                "nominee-1", "NOMINEE", "sess-1", "203.0.113.7", "SUCCESS", null,
                "{}", null, "hash1", NOW);
    }

    @BeforeEach
    void setUp() {
        handler = new MyAuditLogHandler(auditQueryService, jwtService, new ObjectMapper());
    }

    private JwtPayload partyJwt(String sub, PartyType type) {
        return new JwtPayload(sub, type, "s1",
                NOW.getEpochSecond(), NOW.plusSeconds(900).getEpochSecond());
    }

    @Test
    void validParty_returnsOwnerScopedEntries() {
        when(jwtService.validateToken(anyString())).thenReturn(partyJwt("creator-1", PartyType.CREATOR));
        when(auditQueryService.queryForParty(eq("creator-1"), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(2L, List.of(rowWithIp("aid-1"), rowWithIp("aid-2"))));

        ResponseEntity<?> response = handler.query(BEARER, 0, 50, null);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = (Map<String, Object>) ((ApiResponse<?>) response.getBody()).data();
        assertEquals(2L, body.get("total"));
        assertEquals(0, body.get("page"));
        assertEquals(50, body.get("size"));
    }

    @Test
    void usesJwtSubAsPartyId_neverTrustsClientParam() {
        when(jwtService.validateToken(anyString())).thenReturn(partyJwt("nominee-9", PartyType.NOMINEE));
        when(auditQueryService.queryForParty(eq("nominee-9"), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(0L, List.of()));

        handler.query(BEARER, 0, 50, null);

        verify(auditQueryService).queryForParty(eq("nominee-9"), eq(0), eq(50));
    }

    @Test
    void responseOmitsAdminOnlyIpAddress() {
        when(jwtService.validateToken(anyString())).thenReturn(partyJwt("creator-1", PartyType.CREATOR));
        when(auditQueryService.queryForParty(anyString(), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(1L, List.of(rowWithIp("aid-1"))));

        ResponseEntity<?> response = handler.query(BEARER, 0, 50, null);

        Map<String, Object> body = (Map<String, Object>) ((ApiResponse<?>) response.getBody()).data();
        List<Map<String, Object>> entries = (List<Map<String, Object>>) body.get("entries");
        Map<String, Object> entry = entries.get(0);
        assertFalse(entry.containsKey("ipAddress"), "owner-scoped view must not expose ipAddress");
        assertTrue(entry.containsKey("eventType"));
        assertEquals("aid-1", entry.get("auditId"));
    }

    @Test
    void sizeOver200_cappedAt200() {
        when(jwtService.validateToken(anyString())).thenReturn(partyJwt("creator-1", PartyType.CREATOR));
        when(auditQueryService.queryForParty(anyString(), eq(0), eq(200)))
                .thenReturn(new AuditQueryResult(0L, List.of()));

        ResponseEntity<?> response = handler.query(BEARER, 0, 999, null);

        Map<String, Object> body = (Map<String, Object>) ((ApiResponse<?>) response.getBody()).data();
        assertEquals(200, body.get("size"));
    }

    @Test
    void missingBearer_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class, () -> handler.query(null, 0, 50, null));
        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }
}
