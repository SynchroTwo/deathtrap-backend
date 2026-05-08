package in.deathtrap.audit.routes;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.AuditQueryService;
import in.deathtrap.audit.service.AuditQueryService.AuditQueryResult;
import in.deathtrap.audit.config.JwtService;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
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

/** Handles GET /audit/log — admin-only paginated query with optional filters. */
@RestController
@RequestMapping("/audit/log")
public class QueryAuditLogHandler {

    private static final Logger log = LoggerFactory.getLogger(QueryAuditLogHandler.class);

    private final AuditQueryService auditQueryService;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    /** Constructs QueryAuditLogHandler with required dependencies. */
    public QueryAuditLogHandler(AuditQueryService auditQueryService,
                                JwtService jwtService,
                                ObjectMapper objectMapper) {
        this.auditQueryService = auditQueryService;
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
    }

    /** GET /audit/log — returns paginated audit entries; admin JWT required. */
    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> query(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String targetId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.ADMIN) {
            throw AppException.forbidden();
        }

        int effectiveSize = Math.min(size, 200);
        AuditQueryResult result = auditQueryService.query(
                actorId, targetId, eventType, fromDate, toDate, page, effectiveSize);

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
            dto.put("ipAddress", entry.ipAddress());
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

        log.info("Audit log queried: adminId={} total={} page={}", jwt.sub(), result.total(), page);
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
