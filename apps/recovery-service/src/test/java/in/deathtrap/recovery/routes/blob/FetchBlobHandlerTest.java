package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper.RecoveryBlob;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.s3.S3Client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for FetchBlobHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class FetchBlobHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private S3Client s3Client;

    @InjectMocks private FetchBlobHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload lawyerJwt() {
        return new JwtPayload("lawyer-1", PartyType.LAWYER, "s3",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private RecoveryBlob activeBlob() {
        return new RecoveryBlob("blob-1", "creator-1", "recovery/creator-1/blob-1",
                2, "active", Instant.now(), Instant.now());
    }

    private RecoveryBlobLayer myLayer() {
        return new RecoveryBlobLayer("layer-1", "blob-1", 1,
                "nominee-1", "nominee", "pubkey-1", "a".repeat(64), Instant.now());
    }

    // CREATOR: SELECT_ACTIVE_BLOB (1 vararg) → 3 matchers — no layer lookup
    // NOMINEE: SELECT_CREATOR_ID_FOR_NOMINEE (1 vararg), SELECT_ACTIVE_BLOB (1 vararg),
    //          SELECT_MY_LAYER (3 varargs: blobId, partyId, partyType) → 5 matchers
    // LAWYER: SELECT_CREATOR_ID_FOR_LAWYER (1 vararg), SELECT_ACTIVE_BLOB (1 vararg),
    //         SELECT_MY_LAYER (3 varargs) → 5 matchers

    @Test
    void creatorFetchesOwnBlob_returnsNullLayerOrder() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))      // 1-vararg: SELECT_ACTIVE_BLOB
                .thenReturn(List.of(activeBlob()));

        ResponseEntity<?> response = handler.fetchBlob(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void nomineeFetchesBlob_resolvesCreatorId_returnsLayerOrder() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))      // 1-vararg: creatorId resolve + blob
                .thenReturn(List.of("creator-1"))            // SELECT_CREATOR_ID_FOR_NOMINEE
                .thenReturn(List.of(activeBlob()));          // SELECT_ACTIVE_BLOB
        when(dbClient.query(anyString(), any(), any(), any(), any()))  // 3-vararg: SELECT_MY_LAYER
                .thenReturn(List.of(myLayer()));

        ResponseEntity<?> response = handler.fetchBlob(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void lawyerFetchesBlob_resolvesViaLayers_returnsLayerOrder() {
        when(jwtService.validateToken(anyString())).thenReturn(lawyerJwt());
        when(dbClient.query(anyString(), any(), any()))      // 1-vararg
                .thenReturn(List.of("creator-1"))            // SELECT_CREATOR_ID_FOR_LAWYER
                .thenReturn(List.of(activeBlob()));          // SELECT_ACTIVE_BLOB
        when(dbClient.query(anyString(), any(), any(), any(), any()))  // 3-vararg: SELECT_MY_LAYER
                .thenReturn(List.of(myLayer()));

        ResponseEntity<?> response = handler.fetchBlob(BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void nomineeNotActive_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))      // 1-vararg: creator resolve → empty
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.fetchBlob(BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void noActiveBlob_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))      // 1-vararg: blob → not found
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class, () -> handler.fetchBlob(BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }
}
