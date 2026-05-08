package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.BlobLayerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.StoreBlobRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.service.BlobRebuildLogService;
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

/** Unit tests for StoreBlobHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class StoreBlobHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private S3Client s3Client;
    @Mock private BlobRebuildLogService rebuildLogService;

    @InjectMocks private StoreBlobHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String VALID_FP = "a".repeat(64);

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private BlobLayerRequest layer(String partyId, String partyType) {
        return new BlobLayerRequest(partyId, partyType, "pubkey-1", VALID_FP, 1);
    }

    private StoreBlobRequest req(List<BlobLayerRequest> layers) {
        return new StoreBlobRequest("dGVzdA==", layers, "NOMINEE_ADDED");
    }

    // SELECT_PUBKEY takes 3 varargs (pubkeyId, partyId, partyType) → 5 matchers
    // SELECT_NOMINEES takes 1 vararg (creatorId) → 3 matchers
    // SELECT_ACTIVE_BLOB takes 1 vararg (creatorId) → 3 matchers

    @Test
    void validCreatorWith3Layers_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any(), any(), any()))         // 3-vararg: pubkey checks
                .thenReturn(List.of(Boolean.TRUE))
                .thenReturn(List.of(Boolean.TRUE))
                .thenReturn(List.of(Boolean.TRUE));
        when(dbClient.query(anyString(), any(), any()))                       // 1-vararg: nominees, old blob
                .thenReturn(List.of())                                         // nominees (not validated per spec)
                .thenReturn(List.of("old-blob-1"));                           // old active blob
        when(dbClient.withTransaction(any())).thenReturn(null);

        List<BlobLayerRequest> layers = List.of(
                layer("nominee-1", "nominee"),
                layer("nominee-2", "nominee"),
                layer("lawyer-1", "lawyer"));
        ResponseEntity<?> response = handler.storeBlob(req(layers), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void nonCreatorPartyType_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.storeBlob(req(List.of(layer("lawyer-1", "lawyer"))), BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }

    @Test
    void zeroLayers_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.storeBlob(req(List.of()), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void pubkeyNotActive_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any(), any(), any()))         // 3-vararg: pubkey
                .thenReturn(List.of(Boolean.FALSE));                          // not active

        AppException ex = assertThrows(AppException.class,
                () -> handler.storeBlob(req(List.of(layer("lawyer-1", "lawyer"))), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void s3NotConfigured_skipsUploadStillInserts_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any(), any(), any()))         // 3-vararg: pubkey
                .thenReturn(List.of(Boolean.TRUE));
        when(dbClient.query(anyString(), any(), any()))                       // 1-vararg
                .thenReturn(List.of())                                         // nominees
                .thenReturn(List.of());                                        // no old blob
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.storeBlob(
                req(List.of(layer("lawyer-1", "lawyer"))), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void firstEverBlob_noOldBlobId_returns201() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any(), any(), any()))         // 3-vararg: pubkey
                .thenReturn(List.of(Boolean.TRUE));
        when(dbClient.query(anyString(), any(), any()))                       // 1-vararg
                .thenReturn(List.of())                                         // nominees
                .thenReturn(List.of());                                        // no previous blob
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.storeBlob(
                req(List.of(layer("lawyer-1", "lawyer"))), BEARER);

        assertEquals(201, response.getStatusCode().value());
    }

    @Test
    void pubkeyNotFound_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any(), any(), any()))         // 3-vararg: pubkey
                .thenReturn(List.of());                                        // not found

        AppException ex = assertThrows(AppException.class,
                () -> handler.storeBlob(req(List.of(layer("lawyer-1", "lawyer"))), BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }
}
