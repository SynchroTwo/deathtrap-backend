package in.deathtrap.audit.routes;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.audit.config.JwtService;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.AuditQueryService;
import in.deathtrap.audit.service.AuditQueryService.AuditQueryResult;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Handles GET /audit/me — owner-scoped paginated audit query for any authenticated party.
 *
 * <p>Unlike {@code GET /audit/log} (admin-only), this returns only entries where the caller
 * is the actor OR the target, so a creator/nominee/lawyer dashboard can show its own audit
 * history. Admin-only fields are omitted from the response (no {@code ipAddress}).
 */
@RestController
@RequestMapping({"/audit/me", "/audit"})
public class MyAuditLogHandler {

    private static final Logger log = LoggerFactory.getLogger(MyAuditLogHandler.class);

    private final AuditQueryService auditQueryService;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    /** Constructs MyAuditLogHandler with required dependencies. */
    public MyAuditLogHandler(AuditQueryService auditQueryService,
                             JwtService jwtService,
                             ObjectMapper objectMapper) {
        this.auditQueryService = auditQueryService;
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
    }

    /** GET /audit/me (and /audit alias for the dashboard) — owner-scoped paginated
     *  audit entries; any valid party JWT. {@code limit} is accepted as an alias
     *  for {@code size} so the FE's dashboard call ({@code ?limit=10}) works
     *  unchanged (D008 fix). */
    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> query(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) Integer limit) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();

        int effectiveSize = Math.min(limit != null ? limit : size, 200);
        AuditQueryResult result = auditQueryService.queryForParty(partyId, page, effectiveSize);

        List<Map<String, Object>> entries = new ArrayList<>();
        for (AuditLogRow entry : result.entries()) {
            Map<String, Object> dto = new LinkedHashMap<>();
            dto.put("auditId", entry.auditId());
            dto.put("eventType", entry.eventType());
            dto.put("actorId", entry.actorId());
            dto.put("actorType", entry.actorType());
            dto.put("targetId", entry.targetId());
            dto.put("targetType", entry.targetType());
            dto.put("sessionId", entry.sessionId());
            // ipAddress intentionally omitted — admin-only field (owner-scoped view).
            dto.put("result", entry.result());
            dto.put("failureReason", "SUCCESS".equals(entry.result()) ? null : entry.failureReason());
            dto.put("metadataJson", parseMetadata(entry.metadataJson()));
            dto.put("entryHash", entry.entryHash());
            dto.put("createdAt", entry.createdAt().toString());
            entries.add(dto);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("total", result.total());
        response.put("page", page);
        response.put("size", effectiveSize);
        response.put("entries", entries);

        log.info("Owner-scoped audit queried: partyId={} total={} page={}",
                partyId, result.total(), page);
        return ResponseEntity.ok(ApiResponse.ok(response, UUID.randomUUID().toString()));
    }

    private Object parseMetadata(String raw) {
        if (raw == null || raw.isBlank()) { return null; }
        try {
            return objectMapper.readValue(raw, Object.class);
        } catch (Exception e) {
            return raw;
        }
    }
}
