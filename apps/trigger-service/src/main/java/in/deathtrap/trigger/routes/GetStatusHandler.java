package in.deathtrap.trigger.routes;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.trigger.config.JwtService;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper;
import in.deathtrap.trigger.rowmapper.InactivityCheckRowMapper.InactivityCheck;
import in.deathtrap.trigger.rowmapper.TriggerEventRowMapper;
import in.deathtrap.trigger.rowmapper.TriggerEventRowMapper.TriggerEvent;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles GET /trigger/status — returns inactivity check state and active trigger for a creator. */
@RestController
@RequestMapping("/trigger/status")
public class GetStatusHandler {

    private static final Logger log = LoggerFactory.getLogger(GetStatusHandler.class);

    private static final String SELECT_INACTIVITY_CHECK =
            "SELECT * FROM inactivity_checks WHERE creator_id = ? LIMIT 1";
    private static final String SELECT_ACTIVE_TRIGGER =
            "SELECT trigger_id, creator_id, status, threshold_met, threshold_met_at, created_at " +
            "FROM trigger_events WHERE creator_id = ? " +
            "AND status NOT IN ('completed', 'cancelled', 'halted') ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_SOURCES_COUNT =
            "SELECT COUNT(*) FROM trigger_sources WHERE trigger_id = ? AND verified = TRUE";

    private final DbClient dbClient;
    private final JwtService jwtService;

    /** Constructs GetStatusHandler with required dependencies. */
    public GetStatusHandler(DbClient dbClient, JwtService jwtService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
    }

    /** GET /trigger/status — returns inactivity and trigger status for the authenticated creator. */
    @GetMapping
    public ResponseEntity<ApiResponse<StatusResponse>> getStatus(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String creatorId = jwt.sub();

        List<InactivityCheck> checks = dbClient.query(SELECT_INACTIVITY_CHECK,
                InactivityCheckRowMapper.INSTANCE, creatorId);
        InactivityCheck check = checks.isEmpty() ? null : checks.get(0);

        List<TriggerEvent> triggers = dbClient.query(SELECT_ACTIVE_TRIGGER,
                TriggerEventRowMapper.INSTANCE, creatorId);
        TriggerEvent trigger = triggers.isEmpty() ? null : triggers.get(0);

        ActiveTriggerDto activeTrigger = null;
        if (trigger != null) {
            int sourcesReceived = dbClient.queryOne(SELECT_SOURCES_COUNT,
                    (rs, r) -> rs.getInt(1), trigger.triggerId()).orElse(0);
            activeTrigger = new ActiveTriggerDto(
                    trigger.triggerId(), trigger.status(), sourcesReceived,
                    trigger.thresholdMet(), trigger.createdAt().toString());
        }

        log.info("Status fetched: creatorId={}", creatorId);

        return ResponseEntity.ok(ApiResponse.ok(
                new StatusResponse(
                        creatorId,
                        check != null ? check.lastCheckinAt() : null,
                        check != null ? check.nextCheckAt() : null,
                        check != null ? check.alertsSent() : 0,
                        check != null && check.triggered(),
                        activeTrigger),
                UUID.randomUUID().toString()));
    }

    private record ActiveTriggerDto(
            String triggerId, String status, int sourcesReceived,
            boolean thresholdMet, String createdAt) {}

    private record StatusResponse(
            String creatorId,
            Instant lastCheckinAt,
            Instant nextCheckAt,
            int alertsSent,
            boolean inactivityTriggered,
            ActiveTriggerDto activeTrigger) {}
}
