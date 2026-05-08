package in.deathtrap.locker.routes.blob;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.BlobVersionRowMapper.BlobVersion;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for DownloadBlobHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class DownloadBlobHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private S3Presigner s3Presigner;

    @InjectMocks private DownloadBlobHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "session-2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload adminJwt() {
        return new JwtPayload("admin-1", PartyType.ADMIN, "session-3",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private BlobVersion activeBlobVersion() {
        return new BlobVersion("blob-1", "asset-1", "locker-1",
                "locker/locker-1/bank_accounts/blob-1", 5000L, "a".repeat(64),
                1, true, Instant.now(), null);
    }

    // SELECT_LOCKER_FOR_* takes 1 vararg (partyId) → 3 matchers total
    // SELECT_BLOB takes 2 varargs (lockerId, categoryCode) → 4 matchers total

    @Test
    void creatorDownloadsOwnBlob_returnsPresignedUrl() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: locker resolution
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_BLOB
                .thenReturn(List.of(activeBlobVersion()));

        ResponseEntity<?> response = handler.downloadBlob("bank_accounts", BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void nomineeDownloadsCreatorBlob_resolvesLockerReturnsUrl() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: locker resolution
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_BLOB
                .thenReturn(List.of(activeBlobVersion()));

        ResponseEntity<?> response = handler.downloadBlob("bank_accounts", BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void noBlobForCategory_throwsNotFound() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: locker resolution
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_BLOB → empty
                .thenReturn(List.of());

        AppException ex = assertThrows(AppException.class,
                () -> handler.downloadBlob("bank_accounts", BEARER));

        assertEquals(ErrorCode.NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void adminPartyType_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());

        AppException ex = assertThrows(AppException.class,
                () -> handler.downloadBlob("bank_accounts", BEARER));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
