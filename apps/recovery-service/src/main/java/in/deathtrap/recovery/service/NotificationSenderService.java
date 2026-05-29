package in.deathtrap.recovery.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.ActionLinkTokenService;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.Body;
import software.amazon.awssdk.services.ses.model.Content;
import software.amazon.awssdk.services.ses.model.Destination;
import software.amazon.awssdk.services.ses.model.Message;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;

/** E006 Phase 1 Deploy B Chunk 3b — confirmation-flow email fan-out via SES.
 *
 *  Phase 1 ships **email only** (per UI lock at 2026-05-29 10:02 IST §17 #1).
 *  SMS + in-app push are deferred until vendors are picked. This service is
 *  best-effort — failures are logged but never thrown, so the synchronous
 *  HTTP response from UploadDeathCertHandler is never delayed by a slow SES
 *  call (the timeout would otherwise propagate to the FE).
 *
 *  Template copy is inline + hand-written from ClaudeOutput/E006_NOTIFICATION_COPY.md
 *  §1 (cert uploaded — fan-out to creator + nominees + lawyer). The other §2-§5
 *  scenarios (confirm / object / expiry / lawyer-silent fan-outs) will land
 *  in subsequent chunks alongside the worker that triggers them. */
@Service
public class NotificationSenderService {

    private static final Logger log = LoggerFactory.getLogger(NotificationSenderService.class);
    private static final DateTimeFormatter HUMAN_DATE = DateTimeFormatter
            .ofPattern("EEE d MMM, HH:mm 'IST'")
            .withZone(ZoneId.of("Asia/Kolkata"));

    private static final String SELECT_USER =
            "SELECT user_id, full_name, email FROM users WHERE user_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_ACTIVE_NOMINEES =
            "SELECT u.user_id, u.full_name, u.email " +
            "FROM nominees n JOIN users u ON n.nominee_id = u.user_id " +
            "WHERE n.creator_id = ? AND n.status = 'active'::nominee_status_enum";
    private static final String SELECT_LAWYER =
            "SELECT u.user_id, u.full_name, u.email " +
            "FROM locker_meta lm " +
            "JOIN lawyers l ON l.lawyer_id = lm.assigned_lawyer_id " +
            "JOIN users u ON u.user_id = l.lawyer_id " +
            "WHERE lm.user_id = ? AND lm.assigned_lawyer_id IS NOT NULL " +
            "AND l.status = 'active'::lawyer_status_enum LIMIT 1";

    private static final RowMapper<Recipient> RECIPIENT_MAPPER = (rs, row) -> new Recipient(
            rs.getString("user_id"),
            rs.getString("full_name"),
            rs.getString("email"));

    private final DbClient dbClient;
    private final ActionLinkTokenService tokenService;
    private final SesClient sesClient;

    @Value("${SES_FROM_ADDRESS:no-reply@deathtrap.in}")
    private String fromAddress;

    @Value("${FRONTEND_ORIGIN:https://app.deathtrap.in}")
    private String frontendOrigin;

    @Value("${NOTIFICATIONS_ENABLED:false}")
    private boolean notificationsEnabled;

    public NotificationSenderService(DbClient dbClient,
            ActionLinkTokenService tokenService,
            SesClient sesClient) {
        this.dbClient = dbClient;
        this.tokenService = tokenService;
        this.sesClient = sesClient;
    }

    /** Fires the §1 cert-uploaded fan-out to creator + nominees + lawyer (if designated).
     *  Never throws — failures are logged. */
    public void fanOutNewCycle(String creatorId, String windowId, int windowHours,
            String uploaderName, Instant expiresAt, Instant lawyerExpiresAt) {
        if (!notificationsEnabled) {
            log.info("Notifications disabled (NOTIFICATIONS_ENABLED=false); skipping fan-out windowId={}",
                    windowId);
            return;
        }

        // 1. Creator (dead-man's-switch primary)
        try {
            Optional<Recipient> creator = dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId);
            if (creator.isPresent()) {
                sendCreatorEmail(creator.get(), windowId, windowHours, uploaderName, expiresAt);
            }
        } catch (Exception ex) {
            log.error("Creator email fan-out failed: windowId={} creatorId={} err={}",
                    windowId, creatorId, ex.getMessage());
        }

        // 2. Active nominees
        try {
            List<Recipient> nominees = dbClient.query(SELECT_ACTIVE_NOMINEES, RECIPIENT_MAPPER, creatorId);
            for (Recipient n : nominees) {
                try {
                    sendNomineeEmail(n, creatorId, windowId, windowHours, uploaderName, expiresAt);
                } catch (Exception ex) {
                    log.error("Nominee email fan-out failed: windowId={} partyId={} err={}",
                            windowId, n.partyId, ex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.error("Nominee list fan-out failed: windowId={} creatorId={} err={}",
                    windowId, creatorId, ex.getMessage());
        }

        // 3. Lawyer (if designated)
        try {
            Optional<Recipient> lawyer = dbClient.queryOne(SELECT_LAWYER, RECIPIENT_MAPPER, creatorId);
            if (lawyer.isPresent() && lawyerExpiresAt != null) {
                sendLawyerEmail(lawyer.get(), creatorId, windowId, uploaderName, lawyerExpiresAt);
            }
        } catch (Exception ex) {
            log.error("Lawyer email fan-out failed: windowId={} creatorId={} err={}",
                    windowId, creatorId, ex.getMessage());
        }
    }

    private void sendCreatorEmail(Recipient creator, String windowId, int windowHours,
            String uploaderName, Instant expiresAt) {
        String confirmUrl = actionLink(creator.partyId, PartyType.CREATOR, windowId, windowHours, "confirm");
        String objectUrl = actionLink(creator.partyId, PartyType.CREATOR, windowId, windowHours, "object");

        Map<String, String> vars = Map.of(
                "creatorName", nullToEmpty(creator.fullName),
                "uploaderName", nullToEmpty(uploaderName),
                "windowHours", String.valueOf(windowHours),
                "windowExpiresAt", HUMAN_DATE.format(expiresAt),
                "actionUrlConfirm", confirmUrl,
                "actionUrlObject", objectUrl);

        String subject = "Action required — your locker is in a recovery window";
        String body = render(
                "Hi {creatorName},\n\n" +
                "{uploaderName} uploaded a death certificate for your DeathTrap locker. " +
                "If you're reading this, this is a mistake — please object so recovery does not proceed.\n\n" +
                "{windowHours} hours to respond. Silence is treated as consent.\n\n" +
                "Object — stop this recovery: {actionUrlObject}\n" +
                "Confirm — let recovery proceed: {actionUrlConfirm}\n\n" +
                "If you've changed device or lost access and need help reclaiming the locker, " +
                "reply to this email and our team will reach out.\n",
                vars);
        sendEmail(creator.email, subject, body, windowId, "creator");
    }

    private void sendNomineeEmail(Recipient nominee, String creatorId, String windowId,
            int windowHours, String uploaderName, Instant expiresAt) {
        String confirmUrl = actionLink(nominee.partyId, PartyType.NOMINEE, windowId, windowHours, "confirm");
        String objectUrl = actionLink(nominee.partyId, PartyType.NOMINEE, windowId, windowHours, "object");

        Optional<Recipient> creatorOpt = dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId);
        String creatorName = creatorOpt.map(r -> r.fullName).orElse("");

        Map<String, String> vars = Map.of(
                "nomineeName", nullToEmpty(nominee.fullName),
                "creatorName", nullToEmpty(creatorName),
                "uploaderName", nullToEmpty(uploaderName),
                "windowHours", String.valueOf(windowHours),
                "windowExpiresAt", HUMAN_DATE.format(expiresAt),
                "actionUrlConfirm", confirmUrl,
                "actionUrlObject", objectUrl);

        String subject = "Recovery started for " + nullToEmpty(creatorName) + "'s locker";
        String body = render(
                "Hi {nomineeName},\n\n" +
                "{uploaderName} uploaded a death certificate for {creatorName}'s locker. " +
                "A {windowHours}-hour confirmation window has started. " +
                "If you believe this is wrong, please object so recovery is paused.\n\n" +
                "Object — stop this recovery: {actionUrlObject}\n" +
                "Confirm — let recovery proceed: {actionUrlConfirm}\n\n" +
                "If nobody objects, recovery proceeds at {windowExpiresAt}.\n",
                vars);
        sendEmail(nominee.email, subject, body, windowId, "nominee");
    }

    private void sendLawyerEmail(Recipient lawyer, String creatorId, String windowId,
            String uploaderName, Instant lawyerExpiresAt) {
        long hours = Duration.between(Instant.now(), lawyerExpiresAt).toHours();
        String confirmUrl = actionLink(lawyer.partyId, PartyType.LAWYER, windowId, (int) Math.max(hours, 1), "confirm");
        String objectUrl = actionLink(lawyer.partyId, PartyType.LAWYER, windowId, (int) Math.max(hours, 1), "object");

        Optional<Recipient> creatorOpt = dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId);
        String creatorName = creatorOpt.map(r -> r.fullName).orElse("");

        Map<String, String> vars = Map.of(
                "lawyerName", nullToEmpty(lawyer.fullName),
                "creatorName", nullToEmpty(creatorName),
                "uploaderName", nullToEmpty(uploaderName),
                "lawyerExpiresAt", HUMAN_DATE.format(lawyerExpiresAt),
                "actionUrlConfirm", confirmUrl,
                "actionUrlObject", objectUrl);

        String subject = "Mandatory consent required — " + nullToEmpty(creatorName) + "'s locker";
        String body = render(
                "Dear {lawyerName},\n\n" +
                "A death certificate was uploaded by {uploaderName} for your client {creatorName}'s " +
                "DeathTrap locker. As the designated lawyer, your positive consent is required " +
                "for recovery to proceed.\n\n" +
                "You have 168 hours to respond ({lawyerExpiresAt}). Silence is treated as an " +
                "objection, which will pause recovery for 24 hours.\n\n" +
                "Confirm — record your consent: {actionUrlConfirm}\n" +
                "Object — pause this recovery: {actionUrlObject}\n",
                vars);
        sendEmail(lawyer.email, subject, body, windowId, "lawyer");
    }

    private String actionLink(String partyId, PartyType partyType, String windowId, int hours,
            String action) {
        // TTL = window remainder + 15 minute grace per contract §17 #6.
        Duration ttl = Duration.ofHours(hours).plus(Duration.ofMinutes(15));
        String token = tokenService.mint(partyId, partyType, windowId, ttl);
        return frontendOrigin + "/recovery/window/" + windowId + "/" + action + "?token=" + token;
    }

    private void sendEmail(String toAddress, String subject, String body, String windowId, String role) {
        if (toAddress == null || toAddress.isBlank()) {
            log.warn("Skipping email — no address on file: windowId={} role={}", windowId, role);
            return;
        }
        SendEmailRequest req = SendEmailRequest.builder()
                .source(fromAddress)
                .destination(Destination.builder().toAddresses(toAddress).build())
                .message(Message.builder()
                        .subject(Content.builder().data(subject).charset("UTF-8").build())
                        .body(Body.builder()
                                .text(Content.builder().data(body).charset("UTF-8").build())
                                .build())
                        .build())
                .build();
        sesClient.sendEmail(req);
        log.info("SES email sent: windowId={} role={} to={}", windowId, role, mask(toAddress));
    }

    private static String render(String template, Map<String, String> vars) {
        String out = template;
        for (Map.Entry<String, String> e : vars.entrySet()) {
            out = out.replace("{" + e.getKey() + "}", e.getValue());
        }
        return out;
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }

    /** Returns e.g. "a***@example.com" — keeps logs PII-light. */
    private static String mask(String email) {
        int at = email.indexOf('@');
        if (at <= 1) return "***" + email.substring(Math.max(0, at));
        return email.charAt(0) + "***" + email.substring(at);
    }

    /** §2 — confirmation recorded → notify all parties except the confirming one.
     *  Purely informational, no action links. Per copy doc §2. */
    public void fanOutConfirmationRecorded(String windowId, String creatorId,
            String confirmingPartyId, PartyType confirmingPartyType, Instant expiresAt) {
        if (!notificationsEnabled) return;
        try {
            String creatorName = lookupName(creatorId);
            String confirmingPartyName = lookupNameForParty(confirmingPartyId, confirmingPartyType);
            String confirmingPartyRole = roleLabel(confirmingPartyId, confirmingPartyType, creatorId);
            String when = HUMAN_DATE.format(expiresAt);

            String subject = confirmingPartyName + " confirmed — " + creatorName + "'s recovery window";
            String body = "Hi {recipientName},\n\n"
                    + confirmingPartyName + " (" + confirmingPartyRole + ") has confirmed the "
                    + "recovery for " + creatorName + "'s locker. Unless an objection arrives by "
                    + when + ", recovery will proceed.\n";

            sendToAllExcept(creatorId, confirmingPartyId, "confirmation_recorded", windowId,
                    subject, body);
        } catch (Exception ex) {
            log.error("Confirmation fan-out failed: windowId={} err={}", windowId, ex.getMessage());
        }
    }

    /** §3 — objection recorded → cancellation notice to all parties. */
    public void fanOutObjection(String windowId, String creatorId, String objectingPartyId,
            PartyType objectingPartyType, String reason, Instant cooloffUntil) {
        if (!notificationsEnabled) return;
        try {
            String creatorName = lookupName(creatorId);
            String objectingPartyName = lookupNameForParty(objectingPartyId, objectingPartyType);
            String objectingPartyRole = roleLabel(objectingPartyId, objectingPartyType, creatorId);

            String subject = "Recovery cancelled — " + creatorName + "'s locker";
            String reasonBlock = (reason != null && !reason.isBlank())
                    ? "\n> \"" + sanitiseReason(reason) + "\"\n"
                    : "";
            String body = "Hi {recipientName},\n\n"
                    + "The recovery window for " + creatorName + "'s locker has been cancelled.\n\n"
                    + objectingPartyName + " (" + objectingPartyRole + ") submitted an objection."
                    + reasonBlock
                    + "\nA 24-hour cooloff is now in effect (until " + HUMAN_DATE.format(cooloffUntil)
                    + "). After that, any trustee or nominee may upload a fresh death certificate "
                    + "to restart the process.\n";

            sendToAll(creatorId, "objection_recorded", windowId, subject, body);
        } catch (Exception ex) {
            log.error("Objection fan-out failed: windowId={} err={}", windowId, ex.getMessage());
        }
    }

    /** §4 — window expired without objection → recovery proceeding. */
    public void fanOutWindowExpired(String windowId, String creatorId, int windowHours) {
        if (!notificationsEnabled) return;
        try {
            String creatorName = lookupName(creatorId);
            String subject = "Recovery proceeding — " + creatorName + "'s locker";
            String body = "Hi {recipientName},\n\n"
                    + "The " + windowHours + "-hour confirmation window for " + creatorName
                    + "'s locker has closed without any objections. Recovery is now proceeding.\n\n"
                    + "If you're a trustee, you may now begin the peel chain from the app.\n";
            sendToAll(creatorId, "window_expired", windowId, subject, body);
        } catch (Exception ex) {
            log.error("Window-expired fan-out failed: windowId={} err={}", windowId, ex.getMessage());
        }
    }

    /** §5 — lawyer silence at 168h → cancellation. */
    public void fanOutLawyerSilent(String windowId, String creatorId, Instant cooloffUntil) {
        if (!notificationsEnabled) return;
        try {
            String creatorName = lookupName(creatorId);
            Optional<Recipient> lawyerOpt = dbClient.queryOne(SELECT_LAWYER, RECIPIENT_MAPPER, creatorId);
            String lawyerName = lawyerOpt.map(r -> r.fullName).orElse("the designated lawyer");

            String subject = "Recovery cancelled — lawyer did not respond";
            String body = "Hi {recipientName},\n\n"
                    + "The 168-hour mandatory consent window for the designated lawyer ("
                    + lawyerName + ") has expired without a response. Per the locker's "
                    + "configuration, lawyer silence is treated as an objection.\n\n"
                    + "Recovery for " + creatorName + "'s locker is now cancelled. A 24-hour "
                    + "cooloff is in effect (until " + HUMAN_DATE.format(cooloffUntil)
                    + ") before a fresh death certificate may be uploaded.\n";
            sendToAll(creatorId, "lawyer_silent", windowId, subject, body);
        } catch (Exception ex) {
            log.error("Lawyer-silent fan-out failed: windowId={} err={}", windowId, ex.getMessage());
        }
    }

    private void sendToAll(String creatorId, String scenario, String windowId,
            String subject, String bodyTemplate) {
        // Creator
        dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId).ifPresent(creator ->
                sendOne(creator, "creator", scenario, windowId, subject, bodyTemplate));
        // Nominees
        for (Recipient n : dbClient.query(SELECT_ACTIVE_NOMINEES, RECIPIENT_MAPPER, creatorId)) {
            sendOne(n, "nominee", scenario, windowId, subject, bodyTemplate);
        }
        // Lawyer
        dbClient.queryOne(SELECT_LAWYER, RECIPIENT_MAPPER, creatorId).ifPresent(l ->
                sendOne(l, "lawyer", scenario, windowId, subject, bodyTemplate));
    }

    private void sendToAllExcept(String creatorId, String excludePartyId, String scenario,
            String windowId, String subject, String bodyTemplate) {
        dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId).ifPresent(creator -> {
            if (!creator.partyId.equals(excludePartyId)) {
                sendOne(creator, "creator", scenario, windowId, subject, bodyTemplate);
            }
        });
        for (Recipient n : dbClient.query(SELECT_ACTIVE_NOMINEES, RECIPIENT_MAPPER, creatorId)) {
            if (!n.partyId.equals(excludePartyId)) {
                sendOne(n, "nominee", scenario, windowId, subject, bodyTemplate);
            }
        }
        dbClient.queryOne(SELECT_LAWYER, RECIPIENT_MAPPER, creatorId).ifPresent(l -> {
            if (!l.partyId.equals(excludePartyId)) {
                sendOne(l, "lawyer", scenario, windowId, subject, bodyTemplate);
            }
        });
    }

    private void sendOne(Recipient r, String role, String scenario, String windowId,
            String subject, String bodyTemplate) {
        try {
            String body = bodyTemplate.replace("{recipientName}", nullToEmpty(r.fullName));
            sendEmail(r.email, subject, body, windowId, scenario + "/" + role);
        } catch (Exception ex) {
            log.error("Fan-out send failed: scenario={} windowId={} role={} err={}",
                    scenario, windowId, role, ex.getMessage());
        }
    }

    private String lookupName(String userId) {
        return dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, userId)
                .map(r -> r.fullName).orElse("");
    }

    /** Resolves a party's display name. For nominees the partyId is nominee_id;
     *  the underlying user row is keyed on user_id (== nominee_id by our schema). */
    private String lookupNameForParty(String partyId, PartyType type) {
        return dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, partyId)
                .map(r -> r.fullName).orElse(type.name().toLowerCase());
    }

    /** "creator" | "trustee" | "nominee" | "lawyer" — the role label shown in copy. */
    private String roleLabel(String partyId, PartyType type, String creatorId) {
        if (type == PartyType.CREATOR || partyId.equals(creatorId)) return "creator";
        if (type == PartyType.LAWYER) return "lawyer";
        // Nominee — check is_trustee for "trustee" vs "nominee" label.
        Boolean isTrustee = dbClient.queryOne(
                "SELECT is_trustee FROM nominees WHERE nominee_id = ? AND creator_id = ? LIMIT 1",
                (rs, row) -> rs.getBoolean("is_trustee"), partyId, creatorId).orElse(false);
        return isTrustee ? "trustee" : "nominee";
    }

    private static String sanitiseReason(String reason) {
        String trimmed = reason.replace("\r", " ").replace("\n", " ").trim();
        return trimmed.length() > 500 ? trimmed.substring(0, 500) + "…" : trimmed;
    }

    private record Recipient(String partyId, String fullName, String email) {}
}
