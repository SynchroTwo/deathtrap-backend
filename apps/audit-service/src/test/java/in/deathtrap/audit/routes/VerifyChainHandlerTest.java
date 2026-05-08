package in.deathtrap.audit.routes;

import in.deathtrap.audit.config.JwtService;
import in.deathtrap.audit.service.ChainVerifier;
import in.deathtrap.audit.service.ChainVerifier.ChainVerifyResult;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.VerifyChainRequest;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

/** Unit tests for VerifyChainHandler — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("unchecked")
class VerifyChainHandlerTest {

    @Mock private ChainVerifier chainVerifier;
    @Mock private JwtService jwtService;
    @Mock private AuditWriter auditWriter;

    @InjectMocks private VerifyChainHandler handler;

    private static final String BEARER = "Bearer admin-jwt";
    private static final Instant NOW = Instant.parse("2026-05-08T10:00:00.000000Z");

    private JwtPayload adminJwt() {
        return new JwtPayload("admin-1", PartyType.ADMIN, "s1",
                NOW.getEpochSecond(), NOW.plusSeconds(900).getEpochSecond());
    }

    @Test
    void validChain_returnsValidTrueWithEntriesChecked() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(chainVerifier.verify(isNull()))
                .thenReturn(new ChainVerifyResult(true, 10, null, NOW, NOW));

        ResponseEntity<?> response = handler.verify(BEARER, null);

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> body = (Map<String, Object>)
                ((in.deathtrap.common.types.api.ApiResponse<?>) response.getBody()).data();
        assertTrue((Boolean) body.get("valid"));
        assertEquals(10, body.get("entriesChecked"));
        assertNull(body.get("firstInvalidAuditId"));
    }

    @Test
    void tamperedEntry_returnsValidFalseWithFirstInvalidId() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(chainVerifier.verify(isNull()))
                .thenReturn(new ChainVerifyResult(false, 3, "bad-id", NOW, NOW));

        ResponseEntity<?> response = handler.verify(BEARER, null);

        Map<String, Object> body = (Map<String, Object>)
                ((in.deathtrap.common.types.api.ApiResponse<?>) response.getBody()).data();
        assertEquals(false, body.get("valid"));
        assertEquals("bad-id", body.get("firstInvalidAuditId"));
    }

    @Test
    void emptyAuditLog_returnsValidTrueZeroEntries() {
        when(jwtService.validateToken(anyString())).thenReturn(adminJwt());
        when(chainVerifier.verify(isNull()))
                .thenReturn(new ChainVerifyResult(true, 0, null, NOW, NOW));

        ResponseEntity<?> response = handler.verify(BEARER, null);

        Map<String, Object> body = (Map<String, Object>)
                ((in.deathtrap.common.types.api.ApiResponse<?>) response.getBody()).data();
        assertTrue((Boolean) body.get("valid"));
        assertEquals(0, body.get("entriesChecked"));
    }

    @Test
    void nonAdmin_throwsForbidden() {
        when(jwtService.validateToken(anyString()))
                .thenReturn(new JwtPayload("creator-1", PartyType.CREATOR, "s1",
                        NOW.getEpochSecond(), NOW.plusSeconds(900).getEpochSecond()));

        AppException ex = assertThrows(AppException.class,
                () -> handler.verify(BEARER, new VerifyChainRequest(null)));

        assertEquals(ErrorCode.AUTH_FORBIDDEN, ex.getErrorCode());
    }
}
