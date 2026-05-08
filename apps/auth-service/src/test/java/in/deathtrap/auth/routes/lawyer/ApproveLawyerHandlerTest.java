package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.Lawyer;
import in.deathtrap.common.types.dto.ApproveLawyerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.LawyerStatus;
import in.deathtrap.common.types.enums.PartyType;
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

/** Unit tests for ApproveLawyerHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class ApproveLawyerHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private ApproveLawyerHandler handler;

    private static final String BEARER = "Bearer valid-admin-jwt";

    private JwtPayload adminJwt() {
        return new JwtPayload("admin-1", PartyType.ADMIN, "session-admin",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-creator",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private Lawyer pendingLawyer() {
        return new Lawyer("lawyer-1", "Adv. Rajan Mehta", "+919812345678", "rajan@lawfirm.com",
                "Bar Council of Maharashtra", "MH/12345/2010",
                false, null, LawyerStatus.PENDING, false, null,
                Instant.now(), Instant.now());
    }

    private ApproveLawyerRequest validRequest() {
        return new ApproveLawyerRequest("lawyer-1");
    }

    @Test
    void adminApprovePendingLawyer_returnsActive() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(pendingLawyer()));

        ResponseEntity<?> response = handler.approveLawyer(validRequest(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void nonAdminJwt_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.approveLawyer(validRequest(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void lawyerNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.approveLawyer(validRequest(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void lawyerAlreadyActive_throwsConflict() {
        Lawyer active = new Lawyer("lawyer-1", "Adv. Rajan Mehta", "+919812345678", "rajan@lawfirm.com",
                "Bar Council of Maharashtra", "MH/12345/2010",
                true, Instant.now(), LawyerStatus.ACTIVE, true, Instant.now(),
                Instant.now(), Instant.now());
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(active));

        AppException ex = assertThrows(AppException.class,
                () -> handler.approveLawyer(validRequest(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void lawyerSuspended_throwsForbidden() {
        Lawyer suspended = new Lawyer("lawyer-1", "Adv. Rajan Mehta", "+919812345678", "rajan@lawfirm.com",
                "Bar Council of Maharashtra", "MH/12345/2010",
                false, null, LawyerStatus.SUSPENDED, false, null,
                Instant.now(), Instant.now());
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(suspended));

        AppException ex = assertThrows(AppException.class,
                () -> handler.approveLawyer(validRequest(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
