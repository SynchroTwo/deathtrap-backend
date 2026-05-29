package in.deathtrap.locker.routes.backup;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.lang.reflect.Proxy;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for ManagedBackupHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class ManagedBackupHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private ManagedBackupHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String CREATOR_ID = "creator-1";
    private static final String LOCKER_ID = "locker-abc";

    private JwtPayload creatorJwt() {
        return new JwtPayload(CREATOR_ID, PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubLockerRow(boolean enabled, Instant enabledAt) {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(RowMapper.class), eq(CREATOR_ID)))
                .thenAnswer(inv -> {
                    RowMapper m = inv.getArgument(1);
                    return List.of(m.mapRow(stubResultSet(enabled, enabledAt), 0));
                });
    }

    @Test
    void noAuthHeader_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class, () -> handler.getStatus(null));
        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void nonCreatorPartyType_throwsForbidden() {
        JwtPayload nomineeJwt = new JwtPayload("nominee-1", PartyType.NOMINEE, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt);

        AppException ex = assertThrows(AppException.class, () -> handler.getStatus(BEARER));
        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Test
    void noLockerInitialised_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(RowMapper.class), eq(CREATOR_ID)))
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.getStatus(BEARER));
        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void enable_whenAlreadyEnabled_isNoOpAndNoAuditRow() {
        stubLockerRow(true, Instant.now().minusSeconds(3600));

        ResponseEntity<?> resp = handler.enable(BEARER);

        assertEquals(200, resp.getStatusCode().value());
        verify(dbClient, never()).execute(anyString(), any(), any());
        verify(auditWriter, never()).write(any(AuditWritePayload.class));
    }

    @Test
    void disable_whenAlreadyDisabled_isNoOpAndNoAuditRow() {
        stubLockerRow(false, null);

        ResponseEntity<?> resp = handler.disable(BEARER);

        assertEquals(200, resp.getStatusCode().value());
        verify(dbClient, never()).execute(anyString(), any(), any());
        verify(auditWriter, never()).write(any(AuditWritePayload.class));
    }

    @Test
    void enable_whenDisabled_flipsStateAndWritesAuditRow() {
        stubLockerRow(false, null);

        ResponseEntity<?> resp = handler.enable(BEARER);

        assertEquals(200, resp.getStatusCode().value());
        verify(dbClient, times(1)).execute(anyString(), any(Instant.class), eq(LOCKER_ID));
        verify(auditWriter, times(1)).write(any(AuditWritePayload.class));
    }

    @Test
    void disable_whenEnabled_flipsStateAndWritesAuditRow() {
        stubLockerRow(true, Instant.now());

        ResponseEntity<?> resp = handler.disable(BEARER);

        assertEquals(200, resp.getStatusCode().value());
        verify(dbClient, times(1)).execute(anyString(), eq(LOCKER_ID));
        verify(auditWriter, times(1)).write(any(AuditWritePayload.class));
    }

    /** Tiny stub ResultSet exposing only the three columns the handler's mapper reads. */
    private static ResultSet stubResultSet(boolean enabled, Instant enabledAt) {
        return (ResultSet) Proxy.newProxyInstance(
                ManagedBackupHandlerTest.class.getClassLoader(),
                new Class[]{ResultSet.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getString" -> "locker_id".equals(args[0]) ? LOCKER_ID : null;
                    case "getBoolean" -> "managed_backup_enabled".equals(args[0]) ? enabled : false;
                    case "getTimestamp" -> "managed_backup_enabled_at".equals(args[0]) && enabledAt != null
                            ? Timestamp.from(enabledAt) : null;
                    default -> null;
                });
    }
}
