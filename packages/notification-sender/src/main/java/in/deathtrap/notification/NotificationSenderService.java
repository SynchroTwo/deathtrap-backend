package in.deathtrap.notification;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.types.enums.PartyType;
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
    private static final String SELECT_ACTIVE_WRAP_NOMINEES =
            "SELECT u.user_id, u.full_name, u.email " +
            "FROM family_vault_wraps fvw JOIN users u ON u.user_id = fvw.nominee_party_id " +
            "WHERE fvw.creator_id = ? AND fvw.status = 'active'";

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
        if (at <= 1) {
            return "***" + email.substring(Math.max(0, at));
        }
        return email.charAt(0) + "***" + email.substring(at);
    }

    /** §2 — confirmation recorded → notify all parties except the confirming one.
     *  Purely informational, no action links. Per copy doc §2. */
    public void fanOutConfirmationRecorded(String windowId, String creatorId,
            String confirmingPartyId, PartyType confirmingPartyType, Instant expiresAt) {
        if (!notificationsEnabled) {
            return;
        }
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
        if (!notificationsEnabled) {
            return;
        }
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
        if (!notificationsEnabled) {
            return;
        }
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
        if (!notificationsEnabled) {
            return;
        }
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
        if (type == PartyType.CREATOR || partyId.equals(creatorId)) {
            return "creator";
        }
        if (type == PartyType.LAWYER) {
            return "lawyer";
        }
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

    /** E011 Phase 1B §9.1 — account_closure opened (3-cert threshold or missed-payment).
     *  Fans out to: creator (action link with mintClosure token) + each active-wrap nominee. */
    public void fanOutClosureOpened(String creatorId, String closureId, String triggerKind,
            String triggerSummary, Instant objectionWindowEndsAt) {
        if (!notificationsEnabled) {
            log.info("Notifications disabled; skipping closure-opened fan-out closureId={}", closureId);
            return;
        }
        String triggerLabel = humanTriggerLabel(triggerKind);
        String windowEndsHuman = HUMAN_DATE.format(objectionWindowEndsAt);

        // Creator §9.1a — gets the object action link.
        try {
            Optional<Recipient> creator = dbClient.queryOne(SELECT_USER, RECIPIENT_MAPPER, creatorId);
            if (creator.isPresent()) {
                String token = tokenService.mintClosure(creatorId, closureId, Duration.ofDays(7));
                String objectUrl = closureObjectLink(closureId, token);
                String body = "Hi " + nullToEmpty(creator.get().fullName) + ",\n\n"
                        + "A request to close your DeathTrap locker has been registered. This can happen "
                        + "for one of two reasons:\n\n"
                        + "- Three of your nominees have independently confirmed your passing. "
                        + "You're receiving this email because we want to make absolutely sure they're right.\n"
                        + "- A subscription payment has been missed past the grace period.\n\n"
                        + "You have 30 days to object. If you do nothing, the locker will be archived and "
                        + "your nominees will be sent their export.\n\n"
                        + "Object — I'm here and this is a mistake:\n" + objectUrl + "\n\n"
                        + "Reason for this closure: " + triggerLabel + ".\n"
                        + (triggerSummary != null && !triggerSummary.isBlank()
                                ? "Trigger details: " + sanitiseReason(triggerSummary) + ".\n\n" : "\n")
                        + "Your data is still encrypted and unchanged. The objection link above simply "
                        + "records that you're alive and well; recovery flow does not apply to Family Vault lockers.\n";
                sendEmail(creator.get().email,
                        "Action required — account closure window opened for your locker",
                        body, closureId, "creator/closure_opened");
            }
        } catch (Exception ex) {
            log.error("Closure-opened creator fan-out failed: closureId={} err={}", closureId, ex.getMessage());
        }

        // Active-wrap nominees §9.1b — informational, no action.
        try {
            String creatorName = lookupName(creatorId);
            for (Recipient n : dbClient.query(SELECT_ACTIVE_WRAP_NOMINEES, RECIPIENT_MAPPER, creatorId)) {
                try {
                    String body = "Hi " + nullToEmpty(n.fullName) + ",\n\n"
                            + creatorName + "'s DeathTrap locker has entered a 30-day closure window. "
                            + "Closure may have been triggered by independent death-cert uploads or by a "
                            + "missed subscription payment.\n\n"
                            + "During the window, " + creatorName + " can object if they're still reachable. "
                            + "If they don't, the locker will be archived on " + windowEndsHuman
                            + " and you'll receive a notification with instructions to export your copy.\n\n"
                            + "While the window is open:\n"
                            + "- Your read access to the locker continues.\n"
                            + "- No new entries can be added (writes are paused for everyone).\n\n"
                            + "No action is required from you right now.\n";
                    sendEmail(n.email, "Closure window opened — " + creatorName + "'s locker",
                            body, closureId, "nominee/closure_opened");
                } catch (Exception ex) {
                    log.error("Closure-opened nominee fan-out failed: closureId={} partyId={} err={}",
                            closureId, n.partyId, ex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.error("Closure-opened nominee list fan-out failed: closureId={} err={}",
                    closureId, ex.getMessage());
        }
    }

    /** E011 Phase 1B §9.3 — closure finalised (30-day window expired without objection).
     *  Fans out to each active-wrap nominee with the FE-side export-listing URL. */
    public void fanOutClosureFinalised(String creatorId, String closureId) {
        if (!notificationsEnabled) {
            log.info("Notifications disabled; skipping closure-finalised fan-out closureId={}", closureId);
            return;
        }
        try {
            String creatorName = lookupName(creatorId);
            String exportUrl = frontendOrigin + "/nominee/closure/" + closureId + "/export";

            for (Recipient n : dbClient.query(SELECT_ACTIVE_WRAP_NOMINEES, RECIPIENT_MAPPER, creatorId)) {
                try {
                    String body = "Hi " + nullToEmpty(n.fullName) + ",\n\n"
                            + "The 30-day closure window for " + creatorName + "'s locker has closed "
                            + "without an objection. The locker is now archived, and your export is "
                            + "ready to download.\n\n"
                            + "View your export:\n" + exportUrl + "\n\n"
                            + "What's in your export:\n"
                            + "- Every category from " + creatorName + "'s locker, exactly as they last saved.\n"
                            + "- An audit trail of when each entry was created and last edited.\n\n"
                            + "Your export is prepared on this device when you click the link — we don't keep "
                            + "an unencrypted copy on our servers. You can choose to download:\n"
                            + "- An encrypted .fvpack file (only you can decrypt it).\n"
                            + "- A plaintext PDF for printing or sharing.\n"
                            + "- Plaintext JSON for programmatic use.\n\n"
                            + "Your read access to the archived locker continues indefinitely. The export "
                            + "above is just a convenience — you can return any time.\n";
                    sendEmail(n.email,
                            "Locker closed — your export is ready for " + creatorName,
                            body, closureId, "nominee/closure_finalised");
                } catch (Exception ex) {
                    log.error("Closure-finalised nominee fan-out failed: closureId={} partyId={} err={}",
                            closureId, n.partyId, ex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.error("Closure-finalised fan-out failed: closureId={} err={}",
                    closureId, ex.getMessage());
        }
    }

    private String closureObjectLink(String closureId, String token) {
        return frontendOrigin + "/flow/family-vault/closure-object/" + closureId + "?token=" + token;
    }

    private static String humanTriggerLabel(String triggerKind) {
        return switch (triggerKind) {
            case "three_cert_threshold" -> "three independent death-certificate uploads";
            case "missed_payment_grace" -> "a missed subscription payment";
            default -> triggerKind;
        };
    }

    private record Recipient(String partyId, String fullName, String email) {}
}
