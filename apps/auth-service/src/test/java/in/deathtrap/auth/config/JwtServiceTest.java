package in.deathtrap.auth.config;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for JwtService — no Spring context, no mocks. */
class JwtServiceTest {

    private static final String SECRET = "test-jwt-secret-at-least-32-characters-long";

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(SECRET);
    }

    @Test
    void issueToken_returnsNonNullJwt() {
        String token = jwtService.issueToken("user-1", PartyType.CREATOR, "session-1");

        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3);
    }

    @Test
    void validateToken_extractsCorrectClaims() {
        String token = jwtService.issueToken("user-1", PartyType.CREATOR, "session-1");

        JwtPayload payload = jwtService.validateToken(token);

        assertEquals("user-1", payload.sub());
        assertEquals(PartyType.CREATOR, payload.partyType());
        assertEquals("session-1", payload.jti());
        assertTrue(payload.exp() > payload.iat());
    }

    @Test
    void validateToken_withTamperedSignature_throwsSessionInvalid() {
        String token = jwtService.issueToken("user-1", PartyType.CREATOR, "session-1");
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "invalidsignature";

        AppException ex = assertThrows(AppException.class, () -> jwtService.validateToken(tampered));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void validateToken_withDifferentSecret_throwsSessionInvalid() {
        JwtService otherService = new JwtService("different-secret-at-least-32-chars-long!");
        String token = otherService.issueToken("user-1", PartyType.CREATOR, "session-1");

        AppException ex = assertThrows(AppException.class, () -> jwtService.validateToken(token));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void issueVerifiedToken_validatedByValidateVerifiedToken() {
        String token = jwtService.issueVerifiedToken("+919876543210", OtpPurpose.REGISTRATION);

        String partyId = jwtService.validateVerifiedToken(token);

        assertEquals("+919876543210", partyId);
    }

    @Test
    void validateVerifiedToken_withSessionJwt_throwsSessionInvalid() {
        String sessionToken = jwtService.issueToken("user-1", PartyType.CREATOR, "session-1");

        AppException ex = assertThrows(AppException.class,
                () -> jwtService.validateVerifiedToken(sessionToken));

        assertEquals(ErrorCode.AUTH_SESSION_INVALID, ex.getErrorCode());
    }

    @Test
    void issueRefreshToken_returnsNonNullJwt() {
        String token = jwtService.issueRefreshToken("user-1", PartyType.CREATOR, "session-1");

        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3);
    }

    @Test
    void getAccessTokenSeconds_returnsPositiveValue() {
        assertTrue(jwtService.getAccessTokenSeconds() > 0);
    }
}
