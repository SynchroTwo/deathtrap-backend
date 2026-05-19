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

/** Unit tests for UnskipAssetHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
class UnskipAssetHandlerTest {

    @Mock private DbClient dbClient;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;
    @Mock private CompletenessCalculator completenessCalculator;

    @InjectMocks private UnskipAssetHandler handler;

    private static final String BEARER = "Bearer valid-jwt";

    private JwtPayload creatorJwt() {
        return new JwtPayload("creator-1", PartyType.CREATOR, "session-1",
                Instant.now().getEpochSecond(), Instant.now().plusSeconds(900).getEpochSecond());
    }

    private AssetIndex skippedAsset() {
        return new AssetIndex("asset-1", "locker-1", "bank_accounts",
                "online", "skipped", Instant.now(), Instant.now());
    }

    private AssetIndex emptyAsset() {
        return new AssetIndex("asset-1", "locker-1", "bank_accounts",
                "online", "empty", Instant.now(), Instant.now());
    }

    @Test
    void skippedAsset_getsUnskipped_returnsEmptyStatus() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))
                .thenReturn(List.of(skippedAsset()));
        when(dbClient.withTransaction(any())).thenReturn(null);

        ResponseEntity<?> response = handler.unskipAsset("bank_accounts", BEARER);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void notCurrentlySkipped_throwsConflict() {
        when(jwtService.validateToken(anyString())).thenReturn(creatorJwt());
        when(dbClient.query(anyString(), any(), any()))
                .thenReturn(List.of("locker-1"));
        when(dbClient.query(anyString(), any(), any(), any()))
                .thenReturn(List.of(emptyAsset()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.unskipAsset("bank_accounts", BEARER));

        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void missingAuth_throwsUnauthorized() {
        AppException ex = assertThrows(AppException.class,
                () -> handler.unskipAsset("bank_accounts", null));

        assertEquals(ErrorCode.AUTH_UNAUTHORIZED, ex.getErrorCode());
    }
}
