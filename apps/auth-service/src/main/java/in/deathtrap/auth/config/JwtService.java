package in.deathtrap.auth.config;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Issues and validates HS256 JWTs for session authentication. */
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final long EXPIRY_SECONDS = 900L;
    private static final String CLAIM_PARTY_TYPE = "partyType";

    private final SecretKey signingKey;

    /** Constructs JwtService using the provided secret string as the HMAC key. */
    public JwtService(String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Issues a signed JWT with a 15-minute expiry.
     *
     * @param partyId   subject claim
     * @param partyType party type claim
     * @param sessionId JWT ID (jti) claim
     * @return compact signed JWT string
     */
    public String issueToken(String partyId, PartyType partyType, String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(partyId)
                .id(sessionId)
                .claim(CLAIM_PARTY_TYPE, partyType.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(EXPIRY_SECONDS)))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a JWT and returns its payload.
     *
     * @param token the compact JWT string
     * @return parsed JwtPayload
     * @throws AppException AUTH_SESSION_EXPIRED if the token is expired
     * @throws AppException AUTH_SESSION_INVALID if the token is malformed or invalid
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
