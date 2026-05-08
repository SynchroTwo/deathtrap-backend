package in.deathtrap.locker.routes.nominee;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeAssignRequest;
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

/** Unit tests for AssignNomineeHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class AssignNomineeHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private AssignNomineeHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private NomineeAssignRequest validRequest() {
        return new NomineeAssignRequest("asset-1", "nominee-1");
    }

    // SELECT_LOCKER takes 1 vararg (creatorId) → 3 matchers total
    // SELECT_NEXT_ORDER takes 1 vararg (assetId) → 3 matchers total
    // SELECT_ASSET, SELECT_NOMINEE, SELECT_EXISTING_ASSIGNMENT each take 2 varargs → 4 matchers total

    @Test
    void validAssignment_insertedWithDisplayOrder1_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER, SELECT_NEXT_ORDER
                .thenReturn(List.of("locker-1"))                 // SELECT_LOCKER
                .thenReturn(List.of(1L));                        // SELECT_NEXT_ORDER
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET, SELECT_NOMINEE, SELECT_EXISTING_ASSIGNMENT
                .thenReturn(List.of("asset-1"))                  // SELECT_ASSET found
                .thenReturn(List.of("nominee-1"))                // SELECT_NOMINEE active
                .thenReturn(List.of());                          // SELECT_EXISTING_ASSIGNMENT → no duplicate

        ResponseEntity<?> response = handler.assignNominee(validRequest(), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void nomineeNotActive_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET, SELECT_NOMINEE
                .thenReturn(List.of("asset-1"))                  // SELECT_ASSET found
                .thenReturn(List.of());                          // SELECT_NOMINEE → not active

        AppException ex = assertThrows(AppException.class,
                () -> handler.assignNominee(validRequest(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void duplicateAssignment_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET, SELECT_NOMINEE, SELECT_EXISTING
                .thenReturn(List.of("asset-1"))                  // SELECT_ASSET found
                .thenReturn(List.of("nominee-1"))                // SELECT_NOMINEE active
                .thenReturn(List.of("existing-asgn"));           // SELECT_EXISTING → duplicate

        AppException ex = assertThrows(AppException.class,
                () -> handler.assignNominee(validRequest(), BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }
}
