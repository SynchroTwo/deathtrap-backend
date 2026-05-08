package in.deathtrap.locker.config;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Validates HS256 JWTs issued by the auth-service. */
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final String CLAIM_PARTY_TYPE = "partyType";

    private final SecretKey signingKey;

    /** Constructs JwtService using the provided secret as the HMAC key. */
    public JwtService(String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Validates a session JWT and returns its payload.
     * Throws AppException if the token is expired or malformed.
     */
    public JwtPayload validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String partyTypeStr = claims.get(CLAIM_PARTY_TYPE, String.class);
            PartyType partyType = PartyType.valueOf(partyTypeStr);
            return new JwtPayload(
                    claims.getSubject(),
                    partyType,
                    claims.getId(),
                    claims.getIssuedAt().getTime() / 1000L,
                    claims.getExpiration().getTime() / 1000L);
        } catch (ExpiredJwtException ex) {
            log.warn("JWT expired");
            throw AppException.sessionExpired();
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("JWT invalid");
            throw AppException.sessionInvalid();
        }
    }
}
