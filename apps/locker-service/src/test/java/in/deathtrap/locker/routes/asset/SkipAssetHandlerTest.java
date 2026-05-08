package in.deathtrap.locker.routes.asset;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import in.deathtrap.locker.service.CompletenessCalculator;
import in.deathtrap.locker.service.CompletenessCalculator.CompletenessScore;
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

/** Unit tests for SkipAssetHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class SkipAssetHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private CompletenessCalculator completenessCalculator;

    @InjectMocks private SkipAssetHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private AssetIndex emptyAsset() {
        return new AssetIndex("asset-1", "locker-1", "bank_accounts",
                "online", "empty", Instant.now(), Instant.now());
    }

    private AssetIndex filledAsset() {
        return new AssetIndex("asset-1", "locker-1", "bank_accounts",
                "online", "filled", Instant.now(), Instant.now());
    }

    // SELECT_LOCKER takes 1 vararg (creatorId) → 3 matchers total
    // SELECT_ASSET takes 2 varargs (assetId, lockerId) → 4 matchers total

    @Test
    void emptyAsset_getsSkipped_returnsSkippedStatus() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET
                .thenReturn(List.of(emptyAsset()));
        when(dbClient.withTransaction(any())).thenReturn(null);
        when(completenessCalculator.recalculate(anyString()))
                .thenReturn(new CompletenessScore(4, 8, 0));

        ResponseEntity<?> response = handler.skipAsset("asset-1", BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void filledAsset_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))          // 1-vararg: SELECT_LOCKER
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))   // 2-vararg: SELECT_ASSET
                .thenReturn(List.of(filledAsset()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.skipAsset("asset-1", BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }
}
