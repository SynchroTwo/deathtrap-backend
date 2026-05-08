package in.deathtrap.trigger.routes;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.trigger.config.JwtService;
import in.deathtrap.trigger.service.TriggerEventService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles POST /trigger/checkin — records a creator heartbeat to reset the inactivity timer. */
@RestController
@RequestMapping("/trigger/checkin")
public class CheckInHandler {

    private static final Logger log = LoggerFactory.getLogger(CheckInHandler.class);

    private static final String SELECT_USER =
            "SELECT user_id, mobile, status, inactivity_trigger_months FROM users WHERE user_id = ? LIMIT 1";
    private static final String UPSERT_INACTIVITY_CHECK =
            "INSERT INTO inactivity_checks (check_id, creator_id, last_checkin_at, next_check_at, " +
            "alerts_sent, triggered, created_at, updated_at) VALUES (?, ?, NOW(), ?, 0, FALSE, NOW(), NOW()) " +
            "ON CONFLICT (creator_id) DO UPDATE SET last_checkin_at = NOW(), " +
            "next_check_at = EXCLUDED.next_check_at, alerts_sent = 0, triggered = FALSE, updated_at = NOW()";

    private static final RowMapper<CreatorRow> USER_MAPPER = (rs, row) -> new CreatorRow(
            rs.getString("user_id"), rs.getString("status"), rs.getInt("inactivity_trigger_months"));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final TriggerEventService triggerEventService;

    /** Constructs CheckInHandler with required dependencies. */
    public CheckInHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, TriggerEventService triggerEventService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.triggerEventService = triggerEventService;
    }

    /** POST /trigger/checkin — validates JWT, upserts inactivity check, cancels any pending trigger. */
    @PostMapping
    public ResponseEntity<ApiResponse<CheckInResponse>> checkIn(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        String creatorId = jwt.sub();

        List<CreatorRow> users = dbClient.query(SELECT_USER, USER_MAPPER, creatorId);
        if (users.isEmpty()) {
            throw AppException.notFound("user");
        }
        CreatorRow user = users.get(0);
        if (!"active".equals(user.status())) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Creator account is not active");
        }

        Instant nextCheckAt = Instant.now().plus(user.inactivityTriggerMonths() * 30L, ChronoUnit.DAYS);
        dbClient.execute(UPSERT_INACTIVITY_CHECK,
                CsprngUtil.randomUlid(), creatorId, Timestamp.from(nextCheckAt));

        int halted = triggerEventService.haltPendingTriggers(creatorId);
        if (halted > 0) {
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.TRIGGER_HALTED, AuditResult.SUCCESS)
                    .actorId(creatorId).actorType(PartyType.CREATOR)
                    .targetId(creatorId)
                    .metadataJson(Map.of("reason", "creator_checkin"))
                    .build());
        }

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.INACTIVITY_CHECK_RESPONDED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR)
                .targetId(creatorId)
                .metadataJson(Map.of("nextCheckAt", nextCheckAt.toString()))
                .build());

        log.info("Check-in recorded: creatorId={} nextCheckAt={}", creatorId, nextCheckAt);

        return ResponseEntity.ok(ApiResponse.ok(
                new CheckInResponse("Check-in recorded", nextCheckAt.toString(),
                        user.inactivityTriggerMonths()),
                UUID.randomUUID().toString()));
    }

    record CreatorRow(String userId, String status, int inactivityTriggerMonths) {}

    private record CheckInResponse(String message, String nextCheckAt, int inactivityTriggerMonths) {}
}
