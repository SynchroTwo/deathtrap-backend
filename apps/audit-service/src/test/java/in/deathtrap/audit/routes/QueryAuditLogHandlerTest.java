package in.deathtrap.audit.routes;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.audit.config.JwtService;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.AuditQueryService;
import in.deathtrap.audit.service.AuditQueryService.AuditQueryResult;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for QueryAuditLogHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class QueryAuditLogHandlerTest {

    @Mock private AuditQueryService auditQueryService;
    @Mock private JwtService jwtService;

    private QueryAuditLogHandler handler;

    private static final String BEARER = "Bearer admin-jwt";
    private static final Instant NOW = Instant.parse("2026-05-08T10:00:00.000000Z");

    private static AuditLogRow row(String id) {
        return new AuditLogRow(id, "USER_REGISTERED", "actor-1", "CREATOR",
                "target-1", null, null, null, "SUCCESS", null, "{}", null, "hash1", NOW);
    }

    @BeforeEach
    void setUp() {
        handler = new QueryAuditLogHandler(auditQueryService, jwtService, new ObjectMapper());
    }

    private JwtPayload adminJwt() {
        return new JwtPayload("admin-1", PartyType.ADMIN, "s1",
                NOW.getEpochSecond(), NOW.plusSeconds(900).getEpochSecond());
    }

    @Test
    void adminQueriesNoFilters_returnsPaginatedEntries() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(auditQueryService.query(isNull(), isNull(), isNull(), isNull(), isNull(), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(2L, List.of(row("aid-1"), row("aid-2"))));

        ResponseEntity<?> response = handler.query(BEARER, null, null, null, null, null, 0, 50);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = (Map<String, Object>) ((in.deathtrap.common.types.api.ApiResponse<?>) response.getBody()).data();
        assertEquals(2L, body.get("total"));
    }

    @Test
    void adminQueriesWithActorId_sqlIncludesActorFilter() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(auditQueryService.query(eq("actor-1"), isNull(), isNull(), isNull(), isNull(), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(1L, List.of(row("aid-1"))));

        handler.query(BEARER, "actor-1", null, null, null, null, 0, 50);

        verify(auditQueryService).query(eq("actor-1"), isNull(), isNull(), isNull(), isNull(), eq(0), eq(50));
    }

    @Test
    void nonAdminJwt_throwsForbidden() {
        when(jwtService.validateToken(anyString()))
                .thenReturn(new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                        NOW.getEpochSecond(), NOW.plusSeconds(900).getEpochSecond()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.query(BEARER, null, null, null, null, null, 0, 50));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void sizeOver200_cappedAt200() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(auditQueryService.query(isNull(), isNull(), isNull(), isNull(), isNull(), eq(0), eq(200)))
                .thenReturn(new AuditQueryResult(0L, List.of()));

        ResponseEntity<?> response = handler.query(BEARER, null, null, null, null, null, 0, 999);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = (Map<String, Object>) ((in.deathtrap.common.types.api.ApiResponse<?>) response.getBody()).data();
        assertEquals(200, body.get("size"));
    }

    @Test
    void fromDateAndToDateFilters_passedToQuery() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(auditQueryService.query(isNull(), isNull(), isNull(),
                eq("2026-05-01"), eq("2026-05-08"), eq(0), eq(50)))
                .thenReturn(new AuditQueryResult(0L, List.of()));

        handler.query(BEARER, null, null, null, "2026-05-01", "2026-05-08", 0, 50);

        verify(auditQueryService).query(isNull(), isNull(), isNull(),
                eq("2026-05-01"), eq("2026-05-08"), eq(0), eq(50));
    }
}
