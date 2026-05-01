package in.deathtrap.auth.config;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.OtpPurpose;
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

/** Issues and validates HS256 JWTs for session and OTP-verification flows. */
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final String CLAIM_PARTY_TYPE = "partyType";
    private static final String CLAIM_TOKEN_TYPE = "type";
    private static final String CLAIM_PURPOSE = "purpose";
    private static final String TYPE_OTP_VERIFIED = "otp_verified";
    private static final String TYPE_REFRESH = "refresh";

    private final SecretKey signingKey;
    private final long accessTokenSeconds;
    private final long refreshTokenSeconds;

    /** Constructs JwtService using the provided secret string as the HMAC key. */
    public JwtService(String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenSeconds = parseLongEnv("ACCESS_TOKEN_MINUTES", 15L) * 60;
        this.refreshTokenSeconds = parseLongEnv("REFRESH_TOKEN_DAYS", 7L) * 86400;
    }

    /** Issues a signed access JWT (15 min default). Used for all API calls. */
    public String issueToken(String partyId, PartyType partyType, String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(partyId)
                .id(sessionId)
                .claim(CLAIM_PARTY_TYPE, partyType.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenSeconds)))
                .signWith(signingKey)
                .compact();
    }

    /** Issues a signed refresh JWT (7 days default). Used to renew access tokens. */
    public String issueRefreshToken(String partyId, PartyType partyType, String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(partyId)
                .id(sessionId)
                .claim(CLAIM_PARTY_TYPE, partyType.name())
                .claim(CLAIM_TOKEN_TYPE, TYPE_REFRESH)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTokenSeconds)))
                .signWith(signingKey)
                .compact();
    }

    /** Issues a short-lived verified-OTP JWT (15 min). Required by /auth/register. */
    public String issueVerifiedToken(String partyId, OtpPurpose purpose) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(partyId)
                .claim(CLAIM_TOKEN_TYPE, TYPE_OTP_VERIFIED)
                .claim(CLAIM_PURPOSE, purpose.name().toLowerCase())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a verified-OTP token and returns the partyId (mobile number).
     * Throws AppException if the token is invalid, expired, or not of type otp_verified.
     */
    public String validateVerifiedToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String type = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!TYPE_OTP_VERIFIED.equals(type)) {
                throw AppException.sessionInvalid();
            }
            return claims.getSubject();
        } catch (ExpiredJwtException ex) {
            log.warn("Verified token expired");
            throw AppException.sessionExpired();
        } catch (AppException ex) {
            throw ex;
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Verified token invalid");
            throw AppException.sessionInvalid();
        }
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

    /** Returns the configured access token TTL in seconds. */
    public long getAccessTokenSeconds() {
        return accessTokenSeconds;
    }

    private static long parseLongEnv(String name, long defaultValue) {
        String val = System.getenv(name);
        if (val == null || val.isBlank()) { return defaultValue; }
        try { return Long.parseLong(val.trim()); }
        catch (NumberFormatException e) { return defaultValue; }
    }
}
