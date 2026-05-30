package in.deathtrap.notification;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.enums.PartyType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Mints and validates single-use action-link tokens. Two flavours:
 *  - "action-link" tokens bind (windowId, partyId) for the E006 confirmation
 *    window flow (POST /recovery/window/{windowId}/{confirm,object}).
 *  - "closure-object" tokens bind (closureId, creatorId) for the E011 Phase 1B
 *    closure-object flow (POST /locker/family-vault/closure/{closureId}/object).
 *  Lifted into the shared notification-sender package in Phase 1C so both
 *  locker-service and recovery-service can mint without crossing service
 *  boundaries. */
public class ActionLinkTokenService {

    private static final Logger log = LoggerFactory.getLogger(ActionLinkTokenService.class);
    private static final String CLAIM_PARTY_TYPE = "partyType";
    private static final String CLAIM_WINDOW_ID = "windowId";
    private static final String CLAIM_CLOSURE_ID = "closureId";
    private static final String CLAIM_TOKEN_TYPE = "tokenType";
    private static final String TOKEN_TYPE_ACTION_LINK = "action-link";
    private static final String TOKEN_TYPE_CLOSURE_OBJECT = "closure-object";

    private final SecretKey signingKey;

    public ActionLinkTokenService(String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /** Mints a token authorising the given party to confirm or object on the given window. */
    public String mint(String partyId, PartyType partyType, String windowId, Duration ttl) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(partyId)
                .id(windowId + ":" + partyId)
                .claim(CLAIM_PARTY_TYPE, partyType.name())
                .claim(CLAIM_WINDOW_ID, windowId)
                .claim(CLAIM_TOKEN_TYPE, TOKEN_TYPE_ACTION_LINK)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(signingKey)
                .compact();
    }

    /** Verifies the token and asserts it's bound to the given windowId. */
    public ActionLinkClaims verify(String token, String expectedWindowId) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String tokenType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!TOKEN_TYPE_ACTION_LINK.equals(tokenType)) {
                log.warn("Action-link token rejected: wrong tokenType={}", tokenType);
                throw AppException.sessionInvalid();
            }
            String tokenWindowId = claims.get(CLAIM_WINDOW_ID, String.class);
            if (tokenWindowId == null || !tokenWindowId.equals(expectedWindowId)) {
                log.warn("Action-link token rejected: window mismatch (token={}, path={})",
                        tokenWindowId, expectedWindowId);
                throw AppException.sessionInvalid();
            }
            String partyTypeStr = claims.get(CLAIM_PARTY_TYPE, String.class);
            PartyType partyType = PartyType.valueOf(partyTypeStr);
            return new ActionLinkClaims(claims.getSubject(), partyType, tokenWindowId);
        } catch (ExpiredJwtException ex) {
            log.warn("Action-link token expired");
            throw AppException.sessionExpired();
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Action-link token invalid: {}", ex.getMessage());
            throw AppException.sessionInvalid();
        }
    }

    public record ActionLinkClaims(String partyId, PartyType partyType, String windowId) {}

    /** Mints a 7-day closure-object link token (E011 Phase 1B §11.3). Bound to the
     *  creator on a specific closure_id. Refreshed on the 72h reminder. */
    public String mintClosure(String creatorId, String closureId, Duration ttl) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(creatorId)
                .id(closureId + ":" + creatorId)
                .claim(CLAIM_PARTY_TYPE, PartyType.CREATOR.name())
                .claim(CLAIM_CLOSURE_ID, closureId)
                .claim(CLAIM_TOKEN_TYPE, TOKEN_TYPE_CLOSURE_OBJECT)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(signingKey)
                .compact();
    }

    /** Verifies a closure-object token and asserts it's bound to the given closureId.
     *  Returns Optional.empty() on any failure (expired, malformed, wrong type, wrong
     *  closureId). Caller throws FAMILY_VAULT_CLOSURE_TOKEN_INVALID on empty. */
    public Optional<ClosureTokenClaims> verifyClosure(String token, String expectedClosureId) {
        if (token == null || token.isBlank() || expectedClosureId == null) {
            return Optional.empty();
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String tokenType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!TOKEN_TYPE_CLOSURE_OBJECT.equals(tokenType)) {
                log.warn("Closure-object token rejected: wrong tokenType={}", tokenType);
                return Optional.empty();
            }
            String tokenClosureId = claims.get(CLAIM_CLOSURE_ID, String.class);
            if (tokenClosureId == null || !tokenClosureId.equals(expectedClosureId)) {
                log.warn("Closure-object token rejected: closureId mismatch (token={}, path={})",
                        tokenClosureId, expectedClosureId);
                return Optional.empty();
            }
            return Optional.of(new ClosureTokenClaims(claims.getSubject(), tokenClosureId));
        } catch (ExpiredJwtException ex) {
            log.warn("Closure-object token expired");
            return Optional.empty();
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Closure-object token invalid: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    public record ClosureTokenClaims(String creatorId, String closureId) {}

    /** Convenience: convert verifyClosure failure into the 401 AppException. */
    public ClosureTokenClaims verifyClosureOrThrow(String token, String expectedClosureId) {
        return verifyClosure(token, expectedClosureId)
                .orElseThrow(() -> new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_TOKEN_INVALID));
    }
}
