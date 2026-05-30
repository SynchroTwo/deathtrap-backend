package in.deathtrap.auth.routes.dev;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E011 Phase 1C §9.2 — staging-only dev endpoint that mints a session JWT for
 *  any party without going through the OTP flow. Two layers of defence:
 *    1. DEV_ENDPOINTS_ENABLED env var must be 'true' (set on staging only;
 *       never on prod). Anything else returns 403 DEV_ENDPOINT_DISABLED.
 *    2. HMAC via X-Internal-Token header matching INTERNAL_WORKER_SECRET.
 *  Both checks must pass. Audits every mint so the trail is preserved. */
@RestController
@RequestMapping("/auth/dev")
public class DevMintTokenHandler {

    private static final Logger log = LoggerFactory.getLogger(DevMintTokenHandler.class);
    private static final String INTERNAL_HEADER = "X-Internal-Token";
    private static final int MAX_TTL_SECONDS = 24 * 3600;
    private static final int DEFAULT_TTL_SECONDS = 3600;

    private static final String EXISTS_USER =
            "SELECT 1 FROM users WHERE user_id = ? LIMIT 1";
    private static final String EXISTS_NOMINEE =
            "SELECT 1 FROM nominees WHERE nominee_id = ? LIMIT 1";
    private static final String EXISTS_LAWYER =
            "SELECT 1 FROM lawyers WHERE lawyer_id = ? LIMIT 1";

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    @Value("${DEV_ENDPOINTS_ENABLED:false}")
    private String devEndpointsEnabled;

    @Value("${INTERNAL_WORKER_SECRET:}")
    private String internalWorkerSecret;

    public DevMintTokenHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/dev/mint-token — see contract §9.2. */
    @PostMapping("/mint-token")
    public ResponseEntity<ApiResponse<MintResponse>> mintToken(
            @RequestBody @Valid MintRequest request,
            @RequestHeader(value = INTERNAL_HEADER, required = false) String internalToken,
            @RequestHeader(value = "X-Forwarded-For", required = false) String sourceIp) {

        assertDevEnabled();
        assertInternalAuth(internalToken);

        PartyType partyType = parsePartyType(request.partyType());
        assertPartyExists(request.partyId(), partyType);

        int ttlSeconds = request.ttlSeconds() != null ? request.ttlSeconds() : DEFAULT_TTL_SECONDS;
        if (ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
            throw AppException.validationFailed(Map.of(
                    "field", "ttlSeconds",
                    "message", "Must be between 1 and " + MAX_TTL_SECONDS));
        }

        String sessionId = CsprngUtil.randomUlid();
        String token = jwtService.issueToken(request.partyId(), partyType, sessionId);
        Instant expiresAt = Instant.now().plus(Duration.ofSeconds(ttlSeconds));

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.DEV_TOKEN_MINTED, AuditResult.SUCCESS)
                .actorType(PartyType.SYSTEM).targetId(request.partyId())
                .metadataJson(Map.of(
                        "targetPartyId", request.partyId(),
                        "targetPartyType", partyType.name(),
                        "ttlSeconds", ttlSeconds,
                        "sessionId", sessionId,
                        "sourceIp", sourceIp != null ? sourceIp : "unknown"))
                .build());
        log.info("Dev token minted: targetPartyId={} partyType={} ttlSeconds={} sessionId={}",
                request.partyId(), partyType, ttlSeconds, sessionId);

        return ResponseEntity.ok(ApiResponse.ok(
                new MintResponse(token, expiresAt),
                UUID.randomUUID().toString()));
    }

    private void assertDevEnabled() {
        if (!"true".equalsIgnoreCase(devEndpointsEnabled)) {
            throw new AppException(ErrorCode.DEV_ENDPOINT_DISABLED,
                    "Dev endpoints disabled (DEV_ENDPOINTS_ENABLED is not 'true')");
        }
    }

    private void assertInternalAuth(String providedToken) {
        if (internalWorkerSecret == null || internalWorkerSecret.isBlank()) {
            log.warn("Internal worker secret not configured; rejecting dev-mint call");
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Internal worker not configured");
        }
        if (providedToken == null) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Missing internal token");
        }
        byte[] expected = internalWorkerSecret.getBytes();
        byte[] provided = providedToken.getBytes();
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Internal token mismatch");
        }
    }

    private PartyType parsePartyType(String raw) {
        try {
            return PartyType.valueOf(raw.toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw AppException.validationFailed(Map.of(
                    "field", "partyType",
                    "message", "Must be one of CREATOR / NOMINEE / LAWYER"));
        }
    }

    private void assertPartyExists(String partyId, PartyType partyType) {
        String sql = switch (partyType) {
            case CREATOR -> EXISTS_USER;
            case NOMINEE -> EXISTS_NOMINEE;
            case LAWYER -> EXISTS_LAWYER;
            default -> throw AppException.validationFailed(Map.of(
                    "field", "partyType",
                    "message", "Unsupported party type: " + partyType));
        };
        if (dbClient.queryOne(sql, (rs, row) -> 1, partyId).isEmpty()) {
            throw AppException.notFound("party");
        }
    }

    public record MintRequest(
            @NotBlank String partyId,
            @NotBlank String partyType,
            Integer ttlSeconds) {}

    public record MintResponse(String token, Instant expiresAt) {}
}
