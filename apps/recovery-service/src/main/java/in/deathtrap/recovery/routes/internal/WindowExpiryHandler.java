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
import in.deathtrap.notification.ActionLinkTokenService;
import in.deathtrap.notification.NotificationSenderService;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectTaggingRequest;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.Tag;
import software.amazon.awssdk.services.s3.model.Tagging;
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
            "UPDATE account_closure SET status = 'finalising', finalised_at = NOW() " +
            "WHERE closure_id = ? AND status = 'pending_objection'";

    // E011 Phase 1C §6.2 — 72h objection reminder.
    private static final String SELECT_CLOSURES_DUE_72H_REMINDER =
            "SELECT closure_id, creator_id, trigger_kind::text AS trigger_kind, objection_window_ends_at " +
            "FROM account_closure WHERE status = 'pending_objection' " +
            "AND objection_window_ends_at > NOW() " +
            "AND objection_window_ends_at <= NOW() + INTERVAL '72 hours' " +
            "AND reminder_72h_sent_at IS NULL";
    private static final String UPDATE_CLOSURE_72H_REMINDER_SENT =
            "UPDATE account_closure SET reminder_72h_sent_at = NOW() " +
            "WHERE closure_id = ? AND reminder_72h_sent_at IS NULL";

    // E011 Phase 1C §7 — archive flow. Finalising closures pending archive copy.
    private static final String SELECT_FINALISING_CLOSURES_TO_ARCHIVE =
            "SELECT closure_id, creator_id FROM account_closure " +
            "WHERE status = 'finalising' AND archive_complete_at IS NULL";
    private static final String SELECT_LIVE_BLOBS_FOR_CREATOR =
            "SELECT bv.blob_id, bv.s3_key FROM blob_versions bv " +
            "JOIN locker_meta lm ON lm.locker_id = bv.locker_id " +
            "WHERE lm.user_id = ? AND bv.is_current = TRUE";
    private static final String UPDATE_CLOSURE_ARCHIVED =
            "UPDATE account_closure SET status = 'closed', archive_complete_at = NOW(), " +
            "archive_bucket = ?, archive_s3_prefix = ?, archive_object_count = ? " +
            "WHERE closure_id = ? AND status = 'finalising' AND archive_complete_at IS NULL";

    // E011 Phase 1C §6.1 — 7d-post-finalise export-listing reminder.
    private static final String SELECT_CLOSURES_DUE_EXPORT_REMINDER =
            "SELECT closure_id, creator_id FROM account_closure " +
            "WHERE status = 'closed' " +
            "AND finalised_at <= NOW() - INTERVAL '7 days' " +
            "AND export_reminder_sent_at IS NULL " +
            "AND EXISTS (SELECT 1 FROM family_vault_wraps fvw " +
            "            WHERE fvw.creator_id = account_closure.creator_id " +
            "              AND fvw.status = 'active' " +
            "              AND NOT EXISTS (SELECT 1 FROM closure_export_acknowledgement cea " +
            "                              WHERE cea.closure_id = account_closure.closure_id " +
            "                                AND cea.recipient_party_id = fvw.nominee_party_id))";
    private static final String SELECT_UNACKED_NOMINEES_FOR_CLOSURE =
            "SELECT fvw.nominee_party_id FROM family_vault_wraps fvw " +
            "WHERE fvw.creator_id = ? AND fvw.status = 'active' " +
            "AND NOT EXISTS (SELECT 1 FROM closure_export_acknowledgement cea " +
            "                WHERE cea.closure_id = ? AND cea.recipient_party_id = fvw.nominee_party_id)";
    private static final String UPDATE_CLOSURE_EXPORT_REMINDER_SENT =
            "UPDATE account_closure SET export_reminder_sent_at = NOW() " +
            "WHERE closure_id = ? AND export_reminder_sent_at IS NULL";

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
    private static final RowMapper<ClosureDue72hReminder> DUE_72H_MAPPER = (rs, row) -> new ClosureDue72hReminder(
            rs.getString("closure_id"),
            rs.getString("creator_id"),
            rs.getString("trigger_kind"),
            rs.getTimestamp("objection_window_ends_at").toInstant());
    private static final RowMapper<ClosureDueExportReminder> DUE_EXPORT_MAPPER = (rs, row) -> new ClosureDueExportReminder(
            rs.getString("closure_id"),
            rs.getString("creator_id"));
    private static final RowMapper<String> NOMINEE_ID_MAPPER = (rs, row) -> rs.getString("nominee_party_id");
    private static final RowMapper<ClosureToArchive> ARCHIVE_MAPPER = (rs, row) -> new ClosureToArchive(
            rs.getString("closure_id"),
            rs.getString("creator_id"));
    private static final RowMapper<LiveBlob> LIVE_BLOB_MAPPER = (rs, row) -> new LiveBlob(
            rs.getString("blob_id"),
            rs.getString("s3_key"));

    private final DbClient dbClient;
    private final AuditWriter auditWriter;
    private final NotificationSenderService notificationSender;
    private final ActionLinkTokenService actionLinkTokenService;
    private final S3Client s3Client;

    @Value("${INTERNAL_WORKER_SECRET:}")
    private String internalWorkerSecret;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    public WindowExpiryHandler(DbClient dbClient, AuditWriter auditWriter,
            NotificationSenderService notificationSender,
            ActionLinkTokenService actionLinkTokenService,
            S3Client s3Client) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
        this.notificationSender = notificationSender;
        this.actionLinkTokenService = actionLinkTokenService;
        this.s3Client = s3Client;
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

        // E011 Phase 1C §6.1 + §6.2 — reminder legs. Each row's UPDATE-WHERE-NULL
        // guarantees exactly-once delivery across concurrent ticks.
        int reminders72h = tickClosure72hReminders();
        int exportReminders = tickClosureExportReminders();

        // E011 Phase 1C §7 — archive flow. Finalising → closed transition with
        // GLACIER_IR copy of every current blob into the archive prefix.
        int closuresArchived = tickClosureArchive();

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new TickResponse(pending.size(), confirmedCount, lawyerSilentCount,
                        closuresFinalised, reminders72h, exportReminders, closuresArchived),
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

    /** E011 Phase 1C §6.2 — fire 72h objection reminder to creators whose closure
     *  is closing within 72h and hasn't been reminded yet. Mints a fresh 7-day token
     *  per §11.3 LOCKED. UPDATE-WHERE-NULL provides exactly-once delivery. */
    private int tickClosure72hReminders() {
        List<ClosureDue72hReminder> due = dbClient.query(SELECT_CLOSURES_DUE_72H_REMINDER, DUE_72H_MAPPER);
        int fired = 0;
        for (ClosureDue72hReminder c : due) {
            int updated = dbClient.execute(UPDATE_CLOSURE_72H_REMINDER_SENT, c.closureId);
            if (updated == 1) {
                fired++;
                String freshToken = actionLinkTokenService.mintClosure(c.creatorId, c.closureId, Duration.ofDays(7));
                notificationSender.fanOutClosure72hReminder(c.creatorId, c.closureId, freshToken,
                        c.triggerKind, c.objectionWindowEndsAt);
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.FAMILY_VAULT_CLOSURE_REMINDER_72H_SENT, AuditResult.SUCCESS)
                        .actorType(PartyType.SYSTEM).targetId(c.closureId)
                        .metadataJson(Map.of(
                                "closureId", c.closureId,
                                "creatorId", c.creatorId,
                                "objectionWindowEndsAt", c.objectionWindowEndsAt.toString()))
                        .build());
                log.info("72h closure reminder sent: closureId={} creatorId={}", c.closureId, c.creatorId);
            }
        }
        return fired;
    }

    /** E011 Phase 1C §6.1 — fire export-listing reminder to active-wrap nominees
     *  7 days post-finalise who haven't acknowledged fetching their export. One
     *  email per unacked nominee; closure-level timestamp ensures the reminder
     *  fires at most once per closure (per-nominee timestamping deferred — see
     *  Phase 2 polish note in contract §6.1). */
    private int tickClosureExportReminders() {
        List<ClosureDueExportReminder> due = dbClient.query(SELECT_CLOSURES_DUE_EXPORT_REMINDER, DUE_EXPORT_MAPPER);
        int fired = 0;
        for (ClosureDueExportReminder c : due) {
            int updated = dbClient.execute(UPDATE_CLOSURE_EXPORT_REMINDER_SENT, c.closureId);
            if (updated == 1) {
                fired++;
                List<String> unackedNominees = dbClient.query(
                        SELECT_UNACKED_NOMINEES_FOR_CLOSURE, NOMINEE_ID_MAPPER, c.creatorId, c.closureId);
                for (String nomineeId : unackedNominees) {
                    notificationSender.fanOutClosureExportReminder(c.creatorId, c.closureId, nomineeId);
                }
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.FAMILY_VAULT_CLOSURE_EXPORT_REMINDER_SENT, AuditResult.SUCCESS)
                        .actorType(PartyType.SYSTEM).targetId(c.closureId)
                        .metadataJson(Map.of(
                                "closureId", c.closureId,
                                "creatorId", c.creatorId,
                                "nomineesReminded", unackedNominees.size()))
                        .build());
                log.info("Export reminder sent: closureId={} creatorId={} nominees={}",
                        c.closureId, c.creatorId, unackedNominees.size());
            }
        }
        return fired;
    }

    /** E011 Phase 1C §7.1 — archive job. Copies every current blob from the live
     *  prefix to the archive prefix with GLACIER_IR storage class, tags the live
     *  source with closure-archived=true (drives the S3 lifecycle rule), and
     *  atomically flips finalising → closed. Per §14.2 LOCKED the archive uses
     *  the same bucket as live, just a different prefix. Best-effort per-closure
     *  isolation — one failure doesn't block other closures. */
    private int tickClosureArchive() {
        if (s3BucketName == null || s3BucketName.isBlank()) {
            log.warn("S3_BUCKET_NAME not configured; skipping archive tick");
            return 0;
        }
        List<ClosureToArchive> pending = dbClient.query(SELECT_FINALISING_CLOSURES_TO_ARCHIVE, ARCHIVE_MAPPER);
        int archived = 0;
        for (ClosureToArchive c : pending) {
            try {
                String archivePrefix = "archive/closure/" + c.closureId + "/";
                List<LiveBlob> blobs = dbClient.query(SELECT_LIVE_BLOBS_FOR_CREATOR, LIVE_BLOB_MAPPER, c.creatorId);
                List<String> copiedKeys = new ArrayList<>();
                for (LiveBlob b : blobs) {
                    if (b.s3Key == null || b.s3Key.isBlank()) {
                        continue;
                    }
                    String archiveKey = archivePrefix + b.s3Key;
                    s3Client.copyObject(CopyObjectRequest.builder()
                            .sourceBucket(s3BucketName)
                            .sourceKey(b.s3Key)
                            .destinationBucket(s3BucketName)
                            .destinationKey(archiveKey)
                            .storageClass(StorageClass.GLACIER_IR)
                            .build());
                    s3Client.putObjectTagging(PutObjectTaggingRequest.builder()
                            .bucket(s3BucketName)
                            .key(b.s3Key)
                            .tagging(Tagging.builder()
                                    .tagSet(Tag.builder().key("closure-archived").value("true").build())
                                    .build())
                            .build());
                    copiedKeys.add(b.s3Key);
                }
                int updated = dbClient.execute(UPDATE_CLOSURE_ARCHIVED,
                        s3BucketName, archivePrefix, copiedKeys.size(), c.closureId);
                if (updated == 1) {
                    archived++;
                    auditWriter.write(AuditWritePayload
                            .builder(AuditEventType.FAMILY_VAULT_CLOSURE_ARCHIVED, AuditResult.SUCCESS)
                            .actorType(PartyType.SYSTEM).targetId(c.closureId)
                            .metadataJson(Map.of(
                                    "closureId", c.closureId,
                                    "creatorId", c.creatorId,
                                    "archiveBucket", s3BucketName,
                                    "archivePrefix", archivePrefix,
                                    "objectCount", copiedKeys.size()))
                            .build());
                    log.info("Closure archived: closureId={} creatorId={} objectCount={}",
                            c.closureId, c.creatorId, copiedKeys.size());
                }
            } catch (Exception ex) {
                log.error("Archive failed: closureId={} creatorId={} err={}",
                        c.closureId, c.creatorId, ex.getMessage());
            }
        }
        return archived;
    }

    private record PendingWindow(String windowId, String creatorId, int windowHours,
            Instant expiresAt, Instant lawyerExpiresAt, boolean lawyerDesignated) {}

    private record ExpiredClosure(String closureId, String creatorId, Instant objectionWindowEndsAt) {}

    private record ClosureDue72hReminder(String closureId, String creatorId, String triggerKind,
            Instant objectionWindowEndsAt) {}

    private record ClosureDueExportReminder(String closureId, String creatorId) {}

    private record ClosureToArchive(String closureId, String creatorId) {}

    private record LiveBlob(String blobId, String s3Key) {}

    private record TickResponse(int candidates, int confirmed, int lawyerSilent, int closuresFinalised,
            int reminders72h, int exportReminders, int closuresArchived) {}
}
