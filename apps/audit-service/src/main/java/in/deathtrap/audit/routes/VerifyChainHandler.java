package in.deathtrap.audit.routes;

import com.amazonaws.xray.AWSXRay;
import in.deathtrap.audit.config.JwtService;
import in.deathtrap.audit.service.ChainVerifier;
import in.deathtrap.audit.service.ChainVerifier.ChainVerifyResult;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.VerifyChainRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles POST /audit/verify — re-computes the hash chain and returns validity status. */
@RestController
@RequestMapping("/audit/verify")
public class VerifyChainHandler {

    private static final Logger log = LoggerFactory.getLogger(VerifyChainHandler.class);

    private final ChainVerifier chainVerifier;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs VerifyChainHandler with required dependencies. */
    public VerifyChainHandler(ChainVerifier chainVerifier, JwtService jwtService,
                               AuditWriter auditWriter) {
        this.chainVerifier = chainVerifier;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /audit/verify — verifies audit hash chain integrity; admin JWT required. */
    @PostMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> verify(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) VerifyChainRequest request) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.ADMIN) {
            throw AppException.forbidden();
        }

        String fromAuditId = request != null ? request.fromAuditId() : null;

        try {
            AWSXRay.beginSubsegment("audit-chain-verify");
        } catch (Exception ignored) { /* X-Ray not active */ }

        ChainVerifyResult result;
        try {
            result = chainVerifier.verify(fromAuditId);
            try {
                AWSXRay.getCurrentSubsegment().putAnnotation("valid", String.valueOf(result.valid()));
                AWSXRay.getCurrentSubsegment().putAnnotation("entriesChecked",
                        String.valueOf(result.entriesChecked()));
            } catch (Exception ignored) { /* X-Ray not active */ }
        } catch (Exception e) {
            try {
                AWSXRay.getCurrentSubsegment().addException(e);
            } catch (Exception ignored) { /* X-Ray not active */ }
            throw e;
        } finally {
            try { AWSXRay.endSubsegment(); } catch (Exception ignored) { /* X-Ray not active */ }
        }

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.AUDIT_CHAIN_VERIFIED,
                        result.valid() ? AuditResult.SUCCESS : AuditResult.FAILURE)
                .actorId(jwt.sub()).actorType(PartyType.ADMIN)
                .metadataJson(Map.of(
                        "entriesChecked", result.entriesChecked(),
                        "valid", result.valid()))
                .build());

        log.info("Chain verification: adminId={} valid={} entriesChecked={}",
                jwt.sub(), result.valid(), result.entriesChecked());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("valid", result.valid());
        response.put("entriesChecked", result.entriesChecked());
        response.put("firstInvalidAuditId", result.firstInvalidAuditId());
        response.put("verifiedFrom", result.verifiedFrom().toString());
        response.put("verifiedTo", result.verifiedTo().toString());
        response.put("verifiedAt", Instant.now().toString());

        return ResponseEntity.ok(ApiResponse.ok(response, UUID.randomUUID().toString()));
    }
}
