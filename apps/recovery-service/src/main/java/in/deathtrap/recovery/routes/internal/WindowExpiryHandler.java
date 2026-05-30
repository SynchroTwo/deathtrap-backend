package in.deathtrap.recovery.routes.internal;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.notification.NotificationSenderService;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E006 Phase 1 Deploy B Chunk 3a — confirmation_window expiry transitions.
 *
 *  Runs on a 1-minute EventBridge schedule (rate(1 minute) — wired in CDK
 *  separately). For each row in confirmation_window where status='pending':
 *    1. If lawyer_designated=TRUE and NOW() >= lawyer_expires_at and the
 *       lawyer has not responded, flip to lawyer_silent (silence is NOT
 *       consent for the lawyer per contract §9 + spec §"Phase 3 — Window").
 *    2. Else if NOW() >= expires_at, flip to confirmed (silence IS consent
 *       for creator + nominees).
 *
 *  Authenticated via a shared secret header X-Internal-Token (matches
 *  env var INTERNAL_WORKER_SECRET). Constant-time comparison to defeat
 *  timing oracles. Not callable from API Gateway externally — EventBridge
 *  is the only invoker. */
@RestController
@RequestMapping("/recovery/internal/window-tick")
public class WindowExpiryHandler {

    private static final Logger log = LoggerFactory.getLogger(WindowExpiryHandler.class);
    private static final int COOLOFF_HOURS = 24;
    private static final String INTERNAL_HEADER = "X-Internal-Token";

    private static final String SELECT_PENDING_WINDOWS =
            "SELECT window_id, creator_id, window_hours, expires_at, lawyer_expires_at, lawyer_designated " +
            "FROM confirmation_window WHERE status = 'pending' AND " +
            "(expires_at <= NOW() OR (lawyer_designated = TRUE AND lawyer_expires_at <= NOW()))";
    private static final String COUNT_LAWYER_CONFIRM =
            "SELECT COUNT(*) FROM confirmation_responses cr " +
            "JOIN confirmation_window cw ON cr.window_id = cw.window_id " +
            "WHERE cr.window_id = ? AND cr.party_type = 'lawyer' AND cr.action = 'confirm'";
    private static final String UPDATE_LAWYER_SILENT =
            "UPDATE confirmation_window SET status = 'lawyer_silent', resolution_at = NOW(), " +
            "cancelled_reason = 'lawyer_silent_at_168h', cooloff_until = ? " +
            "WHERE window_id = ? AND status = 'pending'";
    private static final String UPDATE_AUTOCONFIRM =
            "UPDATE confirmation_window SET status = 'confirmed', resolution_at = NOW() " +
            "WHERE window_id = ? AND status = 'pending'";
    // E011 Phase 1B §4.4 — closure window expiry leg.
    private static final String SELECT_EXPIRED_CLOSURES =
            "SELECT closure_id, creator_id, objection_window_ends_at FROM account_closure " +
            "WHERE status = 'pending_objection' AND objection_window_ends_at <= NOW()";
    private static final String UPDATE_CLOSURE_FINALISING =
            "UPDATE account_closure SET status = 'finalising' " +
            "WHERE closure_id = ? AND status = 'pending_objection'";

    private static final RowMapper<PendingWindow> PENDING_MAPPER = (rs, row) -> new PendingWindow(
            rs.getString("window_id"),
            rs.getString("creator_id"),
            rs.getInt("window_hours"),
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("lawyer_expires_at") != null
                    ? rs.getTimestamp("lawyer_expires_at").toInstant() : null,
            rs.getBoolean("lawyer_designated"));
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);
    private static final RowMapper<ExpiredClosure> EXPIRED_CLOSURE_MAPPER = (rs, row) -> new ExpiredClosure(
            rs.getString("closure_id"),
            rs.getString("creator_id"),
            rs.getTimestamp("objection_window_ends_at").toInstant());

    private final DbClient dbClient;
    private final AuditWriter auditWriter;
    private final NotificationSenderService notificationSender;

    @Value("${INTERNAL_WORKER_SECRET:}")
    private String internalWorkerSecret;

    public WindowExpiryHandler(DbClient dbClient, AuditWriter auditWriter,
            NotificationSenderService notificationSender) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
        this.notificationSender = notificationSender;
    }

    /** POST /recovery/internal/window-tick — process expiry transitions for pending windows. */
    @PostMapping
    public ResponseEntity<ApiResponse<TickResponse>> tick(
            @RequestHeader(value = INTERNAL_HEADER, required = false) String internalToken) {

        assertInternalAuth(internalToken);

        List<PendingWindow> pending = dbClient.query(SELECT_PENDING_WINDOWS, PENDING_MAPPER);
        Instant now = Instant.now();
        int confirmedCount = 0;
        int lawyerSilentCount = 0;

        for (PendingWindow w : pending) {
            // Lawyer-silent takes precedence: if a lawyer is designated and hasn't confirmed
            // by 168h, the window cancels regardless of where the main expires_at lies.
            if (w.lawyerDesignated && w.lawyerExpiresAt != null
                    && !now.isBefore(w.lawyerExpiresAt)
                    && !hasLawyerConfirmed(w.windowId)) {
                Instant cooloff = now.plus(COOLOFF_HOURS, ChronoUnit.HOURS);
                int updated = dbClient.execute(UPDATE_LAWYER_SILENT,
                        Timestamp.from(cooloff), w.windowId);
                if (updated == 1) {
                    lawyerSilentCount++;
                    auditWriter.write(AuditWritePayload
                            .builder(AuditEventType.CONFIRMATION_LAWYER_SILENT, AuditResult.SUCCESS)
                            .actorType(PartyType.SYSTEM).targetId(w.windowId)
                            .metadataJson(Map.of(
                                    "windowId", w.windowId,
                                    "creatorId", w.creatorId,
                                    "cooloffUntil", cooloff.toString()))
                            .build());
                    log.info("Window flipped lawyer_silent: windowId={} creatorId={}",
                            w.windowId, w.creatorId);
                    // §5 fan-out: cancellation notice to all parties.
                    notificationSender.fanOutLawyerSilent(w.windowId, w.creatorId, cooloff);
                }
            } else if (!now.isBefore(w.expiresAt)) {
                int updated = dbClient.execute(UPDATE_AUTOCONFIRM, w.windowId);
                if (updated == 1) {
                    confirmedCount++;
                    auditWriter.write(AuditWritePayload
                            .builder(AuditEventType.CONFIRMATION_CONFIRMED, AuditResult.SUCCESS)
                            .actorType(PartyType.SYSTEM).targetId(w.windowId)
                            .metadataJson(Map.of(
                                    "windowId", w.windowId,
                                    "creatorId", w.creatorId,
                                    "reason", "expiry_silence_consent"))
                            .build());
                    log.info("Window auto-confirmed by expiry: windowId={} creatorId={}",
                            w.windowId, w.creatorId);
                    // §4 fan-out: recovery proceeding notice to all parties.
                    notificationSender.fanOutWindowExpired(w.windowId, w.creatorId, w.windowHours);
                }
            }
        }

        // E011 Phase 1B §4.4 — closure window expiry leg. Independent of confirmation_window.
        int closuresFinalised = tickAccountClosures();

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new TickResponse(pending.size(), confirmedCount, lawyerSilentCount, closuresFinalised),
                requestId));
    }

    /** Flips expired pending_objection closures to finalising and fires §9.3 fan-out.
     *  Idempotent — UPDATE WHERE status='pending_objection' guarantees one-shot transition. */
    private int tickAccountClosures() {
        List<ExpiredClosure> expired = dbClient.query(SELECT_EXPIRED_CLOSURES, EXPIRED_CLOSURE_MAPPER);
        int finalised = 0;
        for (ExpiredClosure c : expired) {
            int updated = dbClient.execute(UPDATE_CLOSURE_FINALISING, c.closureId);
            if (updated == 1) {
                finalised++;
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.FAMILY_VAULT_CLOSURE_WINDOW_EXPIRED, AuditResult.SUCCESS)
                        .actorType(PartyType.SYSTEM).targetId(c.closureId)
                        .metadataJson(Map.of(
                                "closureId", c.closureId,
                                "creatorId", c.creatorId,
                                "objectionWindowEndsAt", c.objectionWindowEndsAt.toString()))
                        .build());
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.FAMILY_VAULT_CLOSURE_FINALISED, AuditResult.SUCCESS)
                        .actorType(PartyType.SYSTEM).targetId(c.closureId)
                        .metadataJson(Map.of(
                                "closureId", c.closureId,
                                "creatorId", c.creatorId,
                                "trigger", "window_expired_no_objection"))
                        .build());
                log.info("Account closure finalised: closureId={} creatorId={}",
                        c.closureId, c.creatorId);
                notificationSender.fanOutClosureFinalised(c.creatorId, c.closureId);
            }
        }
        return finalised;
    }

    private boolean hasLawyerConfirmed(String windowId) {
        return dbClient.queryOne(COUNT_LAWYER_CONFIRM, INT_MAPPER, windowId).orElse(0) > 0;
    }

    private void assertInternalAuth(String providedToken) {
        if (internalWorkerSecret == null || internalWorkerSecret.isBlank()) {
            log.warn("Internal worker secret not configured; rejecting all calls");
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

    private record PendingWindow(String windowId, String creatorId, int windowHours,
            Instant expiresAt, Instant lawyerExpiresAt, boolean lawyerDesignated) {}

    private record ExpiredClosure(String closureId, String creatorId, Instant objectionWindowEndsAt) {}

    private record TickResponse(int candidates, int confirmed, int lawyerSilent, int closuresFinalised) {}
}
