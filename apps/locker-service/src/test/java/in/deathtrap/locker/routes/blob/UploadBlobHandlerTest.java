package in.deathtrap.locker.routes.blob;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.UploadBlobRequest;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import in.deathtrap.locker.service.CompletenessCalculator;
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

/** Unit tests for UploadBlobHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class UploadBlobHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private S3Client s3Client;
    @Mock private CompletenessCalculator completenessCalculator;

    @InjectMocks private UploadBlobHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String VALID_HASH = "a".repeat(64);

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private AssetIndex activeAsset() {
        return new AssetIndex("asset-1", "locker-1", "bank_accounts",
                "online", "empty", Instant.now(), Instant.now());
    }

    private UploadBlobRequest validRequest() {
        return new UploadBlobRequest("dGVzdA==", 1000L, VALID_HASH, 1);
    }

    // SELECT_LOCKER takes 1 vararg (creatorId) → 3 matchers total
    // SELECT_ASSET takes 2 varargs (lockerId, categoryCode) → 4 matchers total

    @Test
    void validUpload_returns200WithFakeUrlInDev() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET
                .thenReturn(List.of(activeAsset()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.uploadBlob("bank_accounts", validRequest(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void lockerNotFound_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER → empty
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.uploadBlob("bank_accounts", validRequest(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void invalidCategoryCode_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET → empty
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.uploadBlob("invalid_category", validRequest(), BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void sizeBytesTooLarge_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        UploadBlobRequest oversized = new UploadBlobRequest("dGVzdA==", 100_000_001L, VALID_HASH, 1);

        AppException ex = assertThrows(AppException.class,
                () -> handler.uploadBlob("bank_accounts", oversized, BEARER));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void s3NotConfigured_skipsS3UploadReturns200() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET
                .thenReturn(List.of(activeAsset()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.uploadBlob("bank_accounts", validRequest(), BEARER);

        assertEquals(200, response.getStatusCode().value());
    }
}
