package in.deathtrap.recovery.routes.dispute;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.ResolveDisputeRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.DisputeRowMapper.Dispute;
import java.time.Instant;
import java.util.Collections;
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

/** Unit tests for ResolveDisputeHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class ResolveDisputeHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private ResolveDisputeHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String DISPUTE_ID = "dispute-1";

    private JwtPayload adminJwt() {
        return new JwtPayload("admin-1", PartyType.ADMIN, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private Dispute openDispute() {
        return new Dispute(DISPUTE_ID, "session-1", "nominee-1", "nominee",
                "Fraudulent trigger", "open", Instant.now(),
                null, null, null, Instant.now());
    }

    private Dispute resolvedDispute() {
        return new Dispute(DISPUTE_ID, "session-1", "nominee-1", "nominee",
                "Fraudulent trigger", "resolved_proceed", Instant.now(),
                "admin-1", Instant.now(), "looks fine", Instant.now());
    }

    // SELECT_DISPUTE (1 vararg: disputeId) → 3 matchers

    @Test
    void adminResolveProceed_disputeResolvedSessionInProgress() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: dispute
                .thenReturn((List) List.of(openDispute()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.resolveDispute(DISPUTE_ID,
                new ResolveDisputeRequest("resolved_proceed", "all good"), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void adminResolveHalt_disputeResolvedSessionCancelled() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: dispute
                .thenReturn((List) List.of(openDispute()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.resolveDispute(DISPUTE_ID,
                new ResolveDisputeRequest("resolved_halt", "halt confirmed"), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void nonAdmin_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.resolveDispute(DISPUTE_ID,
                        new ResolveDisputeRequest("resolved_proceed", null), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void disputeNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg → empty
                .thenReturn(Collections.emptyList());

        AppException ex = assertThrows(AppException.class,
                () -> handler.resolveDispute(DISPUTE_ID,
                        new ResolveDisputeRequest("resolved_proceed", null), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void alreadyResolvedDispute_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg → resolved dispute
                .thenReturn((List) List.of(resolvedDispute()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.resolveDispute(DISPUTE_ID,
                        new ResolveDisputeRequest("resolved_proceed", null), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }
}
