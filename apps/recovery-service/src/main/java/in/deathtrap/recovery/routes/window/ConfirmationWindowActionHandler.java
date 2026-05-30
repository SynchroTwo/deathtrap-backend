package in.deathtrap.recovery.routes.window;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.notification.ActionLinkTokenService;
import in.deathtrap.notification.ActionLinkTokenService.ActionLinkClaims;
import in.deathtrap.notification.NotificationSenderService;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E006 Phase 1 Deploy B Chunk 2 — confirmation-window action-link endpoints.
 *
 *  Each cycle of the confirmation flow ends when a recipient clicks the
 *  email's "Confirm" or "Object" link. Those clicks land on FE public
 *  pages at creator-hub /recovery/window/:id/{confirm,object,done},
 *  which POST here with the signed action-link token in the Authorization
 *  header.
 *
 *  See ClaudeOutput/E006_BACKEND_CONTRACT.md §9. */
@RestController
@RequestMapping("/recovery/window")
public class ConfirmationWindowActionHandler {

    private static final Logger log = LoggerFactory.getLogger(ConfirmationWindowActionHandler.class);
    private static final int COOLOFF_HOURS = 24;
    private static final String VIA_INAPP = "inapp"; // FE landing page channel marker

    private static final String SELECT_WINDOW =
            "SELECT window_id, creator_id, status, cooloff_until, expires_at, " +
            "lawyer_expires_at, lawyer_designated " +
            "FROM confirmation_window WHERE window_id = ? LIMIT 1";
    private static final String SELECT_EXISTING_RESPONSE =
            "SELECT 1 FROM confirmation_responses WHERE window_id = ? AND party_id = ? LIMIT 1";
    private static final String INSERT_RESPONSE =
            "INSERT INTO confirmation_responses (response_id, window_id, party_id, party_type, " +
            "action, via_channel, reason, responded_at) " +
            "VALUES (?, ?, ?, ?::party_type_enum, ?, ?, ?, NOW())";
    private static final String UPDATE_CONFIRM =
            "UPDATE confirmation_window SET status = 'confirmed', resolution_party_id = ?, " +
            "resolution_at = NOW() WHERE window_id = ? AND status = 'pending'";
    private static final String UPDATE_OBJECT =
            "UPDATE confirmation_window SET status = 'objected', resolution_party_id = ?, " +
            "resolution_at = NOW(), cancelled_reason = ?, cooloff_until = ? " +
            "WHERE window_id = ? AND status = 'pending'";

    private static final RowMapper<Integer> ONE_MAPPER = (rs, row) -> 1;
    private static final RowMapper<WindowRow> WINDOW_MAPPER = (rs, row) -> new WindowRow(
            rs.getString("window_id"),
            rs.getString("creator_id"),
            rs.getString("status"),
            Optional.ofNullable(rs.getTimestamp("cooloff_until")).map(Timestamp::toInstant).orElse(null),
            Optional.ofNullable(rs.getTimestamp("expires_at")).map(Timestamp::toInstant).orElse(null),
            Optional.ofNullable(rs.getTimestamp("lawyer_expires_at")).map(Timestamp::toInstant).orElse(null),
            rs.getBoolean("lawyer_designated"));

    private final DbClient dbClient;
    private final ActionLinkTokenService tokenService;
    private final AuditWriter auditWriter;
    private final NotificationSenderService notificationSender;

    public ConfirmationWindowActionHandler(DbClient dbClient,
            ActionLinkTokenService tokenService, AuditWriter auditWriter,
            NotificationSenderService notificationSender) {
        this.dbClient = dbClient;
        this.tokenService = tokenService;
        this.auditWriter = auditWriter;
        this.notificationSender = notificationSender;
    }

    /** POST /recovery/window/{windowId}/confirm — record a confirmation response. */
    @PostMapping("/{windowId}/confirm")
    public ResponseEntity<ApiResponse<ActionResponse>> confirm(
            @PathVariable String windowId,
            @RequestBody(required = false) @Valid ActionRequest body,
            @RequestHeader("Authorization") String authHeader) {

        ActionLinkClaims claims = parseAuth(authHeader, windowId);
        WindowRow window = loadWindow(windowId);
        assertPending(window);
        assertNotAlreadyResponded(windowId, claims.partyId());

        String responseId = CsprngUtil.randomUlid();
        boolean creatorConfirming = claims.partyType().name().equals("CREATOR")
                && claims.partyId().equals(window.creatorId);
        String newStatus = creatorConfirming ? "confirmed" : "pending";

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_RESPONSE,
                    responseId, windowId, claims.partyId(), claims.partyType().name().toLowerCase(),
                    "confirm", VIA_INAPP, body != null ? body.reason() : null);
            if (creatorConfirming) {
                int updated = dbClient.execute(UPDATE_CONFIRM, claims.partyId(), windowId);
                if (updated != 1) {
                    throw new AppException(ErrorCode.CONFLICT,
                            "Window was not in pending state at flip");
                }
            }
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.CONFIRMATION_CONFIRMED, AuditResult.SUCCESS)
                .actorId(claims.partyId()).actorType(claims.partyType()).targetId(windowId)
                .metadataJson(Map.of(
                        "windowId", windowId,
                        "creatorId", window.creatorId,
                        "newStatus", newStatus,
                        "channel", VIA_INAPP))
                .build());

        log.info("Confirmation recorded: windowId={} partyId={} partyType={} newStatus={}",
                windowId, claims.partyId(), claims.partyType(), newStatus);

        // §2 fan-out: notify all parties except the confirmer.
        notificationSender.fanOutConfirmationRecorded(windowId, window.creatorId,
                claims.partyId(), claims.partyType(),
                window.expiresAt != null ? window.expiresAt : Instant.now());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new ActionResponse(windowId, true, newStatus,
                        creatorConfirming ? window.expiresAt : null),
                requestId));
    }

    /** POST /recovery/window/{windowId}/object — record an objection response. */
    @PostMapping("/{windowId}/object")
    public ResponseEntity<ApiResponse<ActionResponse>> object(
            @PathVariable String windowId,
            @RequestBody(required = false) @Valid ActionRequest body,
            @RequestHeader("Authorization") String authHeader) {

        ActionLinkClaims claims = parseAuth(authHeader, windowId);
        WindowRow window = loadWindow(windowId);
        assertPending(window);
        assertNotAlreadyResponded(windowId, claims.partyId());

        String responseId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        Instant cooloff = now.plus(COOLOFF_HOURS, ChronoUnit.HOURS);
        String reason = body != null && body.reason() != null && !body.reason().isBlank()
                ? body.reason()
                : ("Objection from " + claims.partyType().name().toLowerCase());

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_RESPONSE,
                    responseId, windowId, claims.partyId(), claims.partyType().name().toLowerCase(),
                    "object", VIA_INAPP, body != null ? body.reason() : null);
            int updated = dbClient.execute(UPDATE_OBJECT, claims.partyId(), reason,
                    Timestamp.from(cooloff), windowId);
            if (updated != 1) {
                throw new AppException(ErrorCode.CONFLICT,
                        "Window was not in pending state at flip");
            }
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.CONFIRMATION_OBJECTED, AuditResult.SUCCESS)
                .actorId(claims.partyId()).actorType(claims.partyType()).targetId(windowId)
                .metadataJson(Map.of(
                        "windowId", windowId,
                        "creatorId", window.creatorId,
                        "reason", reason,
                        "cooloffUntil", cooloff.toString(),
                        "channel", VIA_INAPP))
                .build());

        log.info("Objection recorded: windowId={} partyId={} partyType={} cooloffUntil={}",
                windowId, claims.partyId(), claims.partyType(), cooloff);

        // §3 fan-out: cancellation notice to all parties.
        notificationSender.fanOutObjection(windowId, window.creatorId, claims.partyId(),
                claims.partyType(), body != null ? body.reason() : null, cooloff);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new ActionResponse(windowId, true, "objected", cooloff),
                requestId));
    }

    private ActionLinkClaims parseAuth(String authHeader, String windowId) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AppException(ErrorCode.RECOVERY_TOKEN_MISSING,
                    "Action-link token required in Authorization: Bearer header");
        }
        return tokenService.verify(authHeader.substring(7), windowId);
    }

    private WindowRow loadWindow(String windowId) {
        return dbClient.queryOne(SELECT_WINDOW, WINDOW_MAPPER, windowId)
                .orElseThrow(() -> AppException.notFound("confirmation_window"));
    }

    private void assertPending(WindowRow window) {
        if ("pending".equals(window.status)) {
            return;
        }
        switch (window.status) {
            case "objected" -> throw new AppException(ErrorCode.RECOVERY_WINDOW_OBJECTED,
                    "Window was objected at " + window.cooloffUntil);
            case "confirmed" -> throw new AppException(ErrorCode.RECOVERY_WINDOW_CONFIRMED,
                    "Window has already been confirmed");
            default -> throw new AppException(ErrorCode.CONFLICT,
                    "Window is in terminal state: " + window.status);
        }
    }

    private void assertNotAlreadyResponded(String windowId, String partyId) {
        if (dbClient.queryOne(SELECT_EXISTING_RESPONSE, ONE_MAPPER, windowId, partyId).isPresent()) {
            throw new AppException(ErrorCode.RECOVERY_TOKEN_ALREADY_USED,
                    "Party has already responded to this window");
        }
    }

    public record ActionRequest(String reason) {}

    private record WindowRow(String windowId, String creatorId, String status,
            Instant cooloffUntil, Instant expiresAt, Instant lawyerExpiresAt,
            boolean lawyerDesignated) {}

    private record ActionResponse(
            String windowId,
            boolean responseRecorded,
            String newWindowStatus,
            Instant creatorMustWaitUntil
    ) {}
}
