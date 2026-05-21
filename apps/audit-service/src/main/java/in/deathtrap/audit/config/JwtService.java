package in.deathtrap.audit.config;

import in.deathtrap.common.db.DbClient;
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
    private final DbClient db;

    /** Constructs JwtService without revocation checking (tests/local only). */
    public JwtService(String jwtSecret) {
        this(jwtSecret, null);
    }

    /** Constructs JwtService; when db is non-null, validateToken rejects revoked jti. */
    public JwtService(String jwtSecret, DbClient db) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.db = db;
    }

    /**
     * Validates a session JWT and returns its payload.
     * Throws AppException if the token is expired or malformed.
     */
    public JwtPayload validateToken(String token) {
        final JwtPayload payload;
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String partyTypeStr = claims.get(CLAIM_PARTY_TYPE, String.class);
            PartyType partyType = PartyType.valueOf(partyTypeStr);
            payload = new JwtPayload(
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
        assertNotRevoked(payload.jti());
        return payload;
    }

    /** Rejects the token when its jti has been revoked (logout / passphrase change). */
    private void assertNotRevoked(String jti) {
        if (db == null || jti == null) {
            return;
        }
        boolean revoked = db.queryOne("SELECT 1 FROM revoked_tokens WHERE jti = ?",
                (rs, rowNum) -> Boolean.TRUE, jti).isPresent();
        if (revoked) {
            log.warn("JWT revoked (jti present in revoked_tokens)");
            throw AppException.sessionRevoked();
        }
    }
}
