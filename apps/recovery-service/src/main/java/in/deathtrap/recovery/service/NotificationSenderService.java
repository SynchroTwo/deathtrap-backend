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

    private record Recipient(String partyId, String fullName, String email) {}
}
