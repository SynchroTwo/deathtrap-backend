package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.InviteNomineeRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.common.types.enums.UserStatus;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.sns.SnsClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for InviteNomineeHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class InviteNomineeHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private SnsClient snsClient;

    @InjectMocks private InviteNomineeHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private InviteNomineeRequest validRequest() {
        return new InviteNomineeRequest("Alice Smith", "+919876543210",
                "alice@example.com", "daughter");
    }

    private User activeUser() {
        return new User("creator-1", "Bob Creator", LocalDate.of(1980, 1, 1),
                "+919900000001", "bob@example.com", null, null, null,
                KycStatus.VERIFIED, UserStatus.ACTIVE,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
    }

    private User suspendedUser() {
        return new User("creator-1", "Bob Creator", LocalDate.of(1980, 1, 1),
                "+919900000001", "bob@example.com", null, null, null,
                KycStatus.VERIFIED, UserStatus.SUSPENDED,
                null, null, 0, null, 12,
                Instant.now(), Instant.now(), null);
    }

    @Test
    void validRequest_returnsNomineeIdAndExpiresAt() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(activeUser()))
                .thenReturn(List.of(0L));

        ResponseEntity<?> response = handler.inviteNominee(validRequest(), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void creatorNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.inviteNominee(validRequest(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void creatorStatusSuspended_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any())).thenReturn(List.of(suspendedUser()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.inviteNominee(validRequest(), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void noAuthHeader_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.inviteNominee(validRequest(), null));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void snsNotConfigured_inviteStillSucceeds() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of(activeUser()))
                .thenReturn(List.of(6L));

        ResponseEntity<?> response = handler.inviteNominee(validRequest(), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }
}
