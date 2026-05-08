package in.deathtrap.locker.routes.sync;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.rowmapper.AssetIndexRowMapper.AssetIndex;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Unit tests for SyncPullHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class SyncPullHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;

    @InjectMocks private SyncPullHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private AssetIndex sampleAsset(String assetId) {
        Instant now = Instant.now();
        return new AssetIndex(assetId, "locker-1", "bank_accounts", "online", "empty", now, now);
    }

    private List<AssetIndex> twentyFourAssets() {
        List<AssetIndex> assets = new ArrayList<>();
        for (int i = 0; i < 24; i++) {
            assets.add(sampleAsset("asset-" + i));
        }
        return assets;
    }

    // Query vararg counts in SyncPullHandler:
    // SELECT_LOCKER       → 1 vararg (creatorId)          → 3 matchers
    // SELECT_COMPLETENESS → 1 vararg (lockerId)            → 3 matchers
    // SELECT_BLOBS_CHANGED → 2 varargs (lockerId, sinceTs) → 4 matchers
    // SELECT_ASSETS_CHANGED → 3 varargs (lockerId, ts, ts) → 5 matchers
    // SELECT_ASSIGNMENTS_CHANGED → 3 varargs               → 5 matchers

    @Test
    void lastPulledAtZero_returnsAll24AssetsInCreated() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))               // 1-vararg
                .thenReturn((List) Collections.singletonList("locker-1"))  // SELECT_LOCKER
                .thenReturn((List) Collections.singletonList(0));           // SELECT_COMPLETENESS
        when(dbClient.query(anyString(), any(), any(), any()))         // 2-vararg
                .thenReturn((List) Collections.emptyList());               // SELECT_BLOBS_CHANGED
        when(dbClient.query(anyString(), any(), any(), any(), any()))  // 3-vararg
                .thenReturn((List) twentyFourAssets())                     // SELECT_ASSETS_CHANGED
                .thenReturn((List) Collections.emptyList());               // SELECT_ASSIGNMENTS_CHANGED

        ResponseEntity<?> response = handler.syncPull(0L, BEARER);

        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());

        ApiResponse<Map<String, Object>> body = (ApiResponse<Map<String, Object>>) response.getBody();
        Map<String, Object> changes = (Map<String, Object>) body.data().get("changes");
        Map<String, Object> assetIndex = (Map<String, Object>) changes.get("asset_index");
        List<?> created = (List<?>) assetIndex.get("created");
        assertEquals(24, created.size());
    }

    @Test
    void recentLastPulledAt_returnsOnlyChangedAssets() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        long recentMillis = Instant.now().minusSeconds(60).toEpochMilli();
        Instant since = Instant.ofEpochMilli(recentMillis);

        AssetIndex changedAsset = new AssetIndex("asset-0", "locker-1", "bank_accounts",
                "online", "filled",
                since.minusSeconds(3600),  // created before since
                Instant.now());            // updated after since

        when(dbClient.query(anyString(), any(), any()))               // 1-vararg
                .thenReturn((List) Collections.singletonList("locker-1"))  // SELECT_LOCKER
                .thenReturn((List) Collections.singletonList(4));           // SELECT_COMPLETENESS
        when(dbClient.query(anyString(), any(), any(), any()))         // 2-vararg
                .thenReturn((List) Collections.emptyList());               // SELECT_BLOBS_CHANGED
        when(dbClient.query(anyString(), any(), any(), any(), any()))  // 3-vararg
                .thenReturn((List) Collections.singletonList(changedAsset))// SELECT_ASSETS_CHANGED
                .thenReturn((List) Collections.emptyList());               // SELECT_ASSIGNMENTS_CHANGED

        ResponseEntity<?> response = handler.syncPull(recentMillis, BEARER);

        assertEquals(200, response.getStatusCode().value());

        ApiResponse<Map<String, Object>> body = (ApiResponse<Map<String, Object>>) response.getBody();
        Map<String, Object> changes = (Map<String, Object>) body.data().get("changes");
        Map<String, Object> assetIndex = (Map<String, Object>) changes.get("asset_index");
        List<?> created = (List<?>) assetIndex.get("created");
        List<?> updated = (List<?>) assetIndex.get("updated");
        assertEquals(0, created.size());
        assertEquals(1, updated.size());
    }
}
