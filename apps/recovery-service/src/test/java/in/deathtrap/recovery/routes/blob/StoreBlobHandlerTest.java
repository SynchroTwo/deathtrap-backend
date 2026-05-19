package in.deathtrap.recovery.routes.blob;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.BlobLayerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.StoreBlobRequest;
import in.deathtrap.common.types.dto.StoreBlobResponse;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.service.BlobRebuildLogService;
import in.deathtrap.recovery.service.RecoveryBlobRateLimit;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.s3.S3Client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

/** Unit tests for StoreBlobHandler v1.
 *  Covers the 10 validation rules from docs/RECOVERY_SPEC_V1_BACKEND_CHANGES.md §4. */
@ExtendWith(MockitoExtension.class)
class StoreBlobHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private S3Client s3Client;
    @Mock private BlobRebuildLogService rebuildLogService;
    @Mock private RecoveryBlobRateLimit rateLimit;

    @InjectMocks private StoreBlobHandler handler;

    private static final String BEARER = "Bearer valid-jwt";
    private static final String VALID_BLOB_ID = "1e2c3a44-9b10-4d51-bfe2-77c8a2419f01";
    private static final String LAWYER_ID = "8f429100-ec91-4a9d-bc9b-cffd940142c8";
    private static final String NOMINEE_ID_1 = "c2d0a4f1-1234-4ef2-9876-aaaaaaaaaaaa";
    private static final String NOMINEE_ID_2 = "c2d0a4f1-5678-4ef2-9876-bbbbbbbbbbbb";

    /** Realistic-shaped SPKI PEM. Fingerprint computed below by the same algorithm
     *  the handler uses (strip PEM headers + whitespace, base64-decode, SHA-256 hex). */
    private static final String LAWYER_PEM =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAExf7tQk/2I+aZkUm9HKTfLHvNRoFkOZD5\n" +
            "lawyer123456789012345abcdefgh1234567890ABCDEFGHIJKLMNOPQRSTUVWX==\n" +
            "-----END PUBLIC KEY-----";
    private static final String NOMINEE_1_PEM =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAExf7tQk/2I+aZkUm9HKTfLHvNRoFkOZD5\n" +
            "nominee1ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234==\n" +
            "-----END PUBLIC KEY-----";
    private static final String NOMINEE_2_PEM =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAExf7tQk/2I+aZkUm9HKTfLHvNRoFkOZD5\n" +
            "nominee2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz5678==\n" +
            "-----END PUBLIC KEY-----";

    private static final String LAWYER_FP = fingerprint(LAWYER_PEM);
    private static final String NOMINEE_1_FP = fingerprint(NOMINEE_1_PEM);
    private static final String NOMINEE_2_FP = fingerprint(NOMINEE_2_PEM);

    private static String fingerprint(String pem) {
        String b64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        return Sha256Util.hashHex(Base64.getDecoder().decode(b64));
    }

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private JwtPayload nomineeJwt() {
        return new JwtPayload("nominee-1", PartyType.NOMINEE, "s2",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private BlobLayerRequest layer(int order, String partyId, String partyType, String fp) {
        return new BlobLayerRequest(partyId, partyType, fp, order);
    }

    private StoreBlobRequest validReq() {
        return new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(
                        layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)
                ),
                "initial");
    }

    /** Wires the standard mocks needed for a successful upload:
     *   - JWT validates as creator
     *   - rate limit passes
     *   - blob_id collision check returns empty
     *   - existence checks return present (1 row)
     *   - active pubkey resolves with matching fingerprint
     *   - SELECT_ACTIVE_BLOB (creator's old blob) returns empty (no old blob)
     *   - SELECT_CREATOR_BLOB_COUNT returns 0
     *   - withTransaction returns null
     */
    private void wireHappyPath() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        doNothing().when(rateLimit).check(anyString());

        // Use thenAnswer to route based on SQL query text — multiple queryOne signatures
        // hit the same matcher, so we have to disambiguate.
        when(dbClient.queryOne(anyString(), any(), anyString()))
                .thenAnswer(this::routeQueryOneSingle);
        when(dbClient.queryOne(anyString(), any(), anyString(), anyString()))
                .thenAnswer(this::routeQueryOnePair);
        when(dbClient.query(anyString(), any(), anyString()))
                .thenAnswer(invocation -> List.of()); // no old active blob
        when(dbClient.withTransaction(any())).thenReturn(null);
    }

    private Object routeQueryOneSingle(InvocationOnMock invocation) {
        String sql = invocation.getArgument(0);
        if (sql.contains("FROM recovery_blobs WHERE blob_id")) {
            return Optional.empty(); // no collision
        }
        if (sql.contains("COUNT(*) FROM recovery_blobs WHERE creator_id")) {
            return Optional.of(0);
        }
        if (sql.contains("FROM lawyers")) {
            return Optional.of(1); // lawyer active + KYC approved (1-arg variant)
        }
        return Optional.empty();
    }

    private Object routeQueryOnePair(InvocationOnMock invocation) {
        String sql = invocation.getArgument(0);
        Object arg1 = invocation.getArgument(2);
        if (sql.contains("FROM nominees") && sql.contains("creator_id")) {
            return Optional.of(1); // nominee owned by creator (2-arg: partyId, creatorId)
        }
        if (sql.contains("FROM party_public_keys")) {
            // Return the matching PubkeyRow for the queried party (arg1 = partyId)
            String partyId = (String) arg1;
            String pem;
            if (LAWYER_ID.equals(partyId)) {
                pem = LAWYER_PEM;
            } else if (NOMINEE_ID_1.equals(partyId)) {
                pem = NOMINEE_1_PEM;
            } else if (NOMINEE_ID_2.equals(partyId)) {
                pem = NOMINEE_2_PEM;
            } else {
                return Optional.empty();
            }
            return Optional.of(new StoreBlobHandler.PubkeyRow("pk-" + partyId, pem));
        }
        return Optional.empty();
    }

    @Test
    void validV1Request_returns201WithVersion1() {
        wireHappyPath();

        ResponseEntity<ApiResponse<StoreBlobResponse>> response = handler.storeBlob(validReq(), BEARER);

        assertEquals(201, response.getStatusCode().value());
        StoreBlobResponse body = response.getBody().data();
        assertNotNull(body);
        assertEquals(VALID_BLOB_ID, body.blobId());
        assertEquals(1, body.version());
    }

    @Test
    void unknownSpecVersion_throwsRecoveryUnsupportedSpecVersion() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        StoreBlobRequest bad = new StoreBlobRequest(
                "v99", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_UNSUPPORTED_SPEC_VERSION, ex.getErrorCode());
    }

    @Test
    void invalidBlobIdFormat_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", "not-a-uuid", "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void invalidRebuildReason_throwsValidationFailed() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)),
                "GARBAGE_REASON");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void layerCountTooFew_throwsLayerCountOutOfBounds() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS, ex.getErrorCode());
    }

    @Test
    void layerCountTooMany_throwsLayerCountOutOfBounds() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        List<BlobLayerRequest> tooMany = List.of(
                layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP),
                layer(3, NOMINEE_ID_2, "nominee", NOMINEE_2_FP),
                layer(4, "00000000-0000-4000-8000-000000000004", "nominee", "0".repeat(64)),
                layer(5, "00000000-0000-4000-8000-000000000005", "nominee", "0".repeat(64)),
                layer(6, "00000000-0000-4000-8000-000000000006", "nominee", "0".repeat(64)),
                layer(7, "00000000-0000-4000-8000-000000000007", "nominee", "0".repeat(64)),
                layer(8, "00000000-0000-4000-8000-000000000008", "nominee", "0".repeat(64))
        );
        StoreBlobRequest bad = new StoreBlobRequest("v1", VALID_BLOB_ID, "dGVzdA==", tooMany, "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS, ex.getErrorCode());
    }

    @Test
    void firstLayerIsNotLawyer_throwsRecoveryInvalidRecipientOrder() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        doNothing().when(rateLimit).check(anyString());
        when(dbClient.queryOne(anyString(), any(), anyString())).thenAnswer(this::routeQueryOneSingle);

        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, NOMINEE_ID_1, "nominee", NOMINEE_1_FP),
                        layer(2, LAWYER_ID, "lawyer", LAWYER_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_INVALID_RECIPIENT_ORDER, ex.getErrorCode());
    }

    @Test
    void duplicatePartyId_throwsRecoveryDuplicateRecipient() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        doNothing().when(rateLimit).check(anyString());
        when(dbClient.queryOne(anyString(), any(), anyString())).thenAnswer(this::routeQueryOneSingle);

        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP),
                        layer(3, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_DUPLICATE_RECIPIENT, ex.getErrorCode());
    }

    @Test
    void layerOrderHasGap_throwsRecoveryInvalidLayerOrdering() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        doNothing().when(rateLimit).check(anyString());
        when(dbClient.queryOne(anyString(), any(), anyString())).thenAnswer(this::routeQueryOneSingle);

        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, "dGVzdA==",
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(3, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_INVALID_LAYER_ORDERING, ex.getErrorCode());
    }

    @Test
    void blobTooLarge_throwsBlobTooLarge() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        String huge = "A".repeat(32 * 1024 + 1);
        StoreBlobRequest bad = new StoreBlobRequest(
                "v1", VALID_BLOB_ID, huge,
                List.of(layer(1, LAWYER_ID, "lawyer", LAWYER_FP),
                        layer(2, NOMINEE_ID_1, "nominee", NOMINEE_1_FP)),
                "initial");

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(bad, BEARER));
        assertEquals(ErrorCode.RECOVERY_BLOB_TOO_LARGE, ex.getErrorCode());
    }

    @Test
    void rateLimitExceeded_throwsRateLimited() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        org.mockito.Mockito.doThrow(AppException.rateLimited()).when(rateLimit).check(anyString());

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(validReq(), BEARER));
        assertEquals(ErrorCode.RATE_LIMITED, ex.getErrorCode());
    }

    @Test
    void nonCreatorPartyType_throwsForbidden() {
        when(jwtService.validateToken(anyString())).thenReturn(nomineeJwt());

        AppException ex = assertThrows(AppException.class, () -> handler.storeBlob(validReq(), BEARER));
        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
