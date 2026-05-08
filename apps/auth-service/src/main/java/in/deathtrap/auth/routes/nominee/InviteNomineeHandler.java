package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.User;
import in.deathtrap.common.types.dto.InviteNomineeRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeInviteResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.common.types.enums.UserStatus;
import jakarta.validation.Valid;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.sns.SnsClient;

/** Handles nominee invitation by an authenticated creator. */
@RestController
@RequestMapping("/auth/nominee")
public class InviteNomineeHandler {

    private static final Logger log = LoggerFactory.getLogger(InviteNomineeHandler.class);
    private static final int INVITE_DAYS = 7;
    private static final int INVITE_WARN_THRESHOLD = 5;

    private static final String SELECT_USER =
            "SELECT user_id, full_name, date_of_birth, mobile, email, address, pan_ref, aadhaar_ref, " +
            "kyc_status, status, risk_accepted_at, zero_nominee_risk_version, locker_completeness_pct, " +
            "last_reviewed_at, inactivity_trigger_months, created_at, updated_at, deleted_at " +
            "FROM users WHERE user_id = ? AND deleted_at IS NULL LIMIT 1";
    private static final String COUNT_NOMINEES =
            "SELECT COUNT(*) FROM nominees WHERE creator_id = ? AND status != 'removed'::nominee_status_enum";
    private static final String INSERT_NOMINEE =
            "INSERT INTO nominees (nominee_id, creator_id, full_name, mobile, email, relationship, " +
            "registration_order, invite_token_hash, invite_expires_at, status, fingerprint_verified, " +
            "created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'invited'::nominee_status_enum, false, ?, ?)";

    private static final RowMapper<User> USER_MAPPER = (rs, row) -> new User(
            rs.getString("user_id"), rs.getString("full_name"),
            rs.getDate("date_of_birth").toLocalDate(),
            rs.getString("mobile"), rs.getString("email"),
            rs.getString("address"), rs.getString("pan_ref"), rs.getString("aadhaar_ref"),
            KycStatus.valueOf(rs.getString("kyc_status").toUpperCase()),
            UserStatus.valueOf(rs.getString("status").toUpperCase()),
            rs.getTimestamp("risk_accepted_at") != null ? rs.getTimestamp("risk_accepted_at").toInstant() : null,
            rs.getObject("zero_nominee_risk_version", Integer.class),
            rs.getInt("locker_completeness_pct"),
            rs.getTimestamp("last_reviewed_at") != null ? rs.getTimestamp("last_reviewed_at").toInstant() : null,
            rs.getInt("inactivity_trigger_months"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant(),
            rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toInstant() : null);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final SnsClient snsClient;

    @Value("${SNS_OTP_ARN:}")
    private String snsOtpArn;

    @Value("${ENVIRONMENT:local}")
    private String environment;

    /** Constructs InviteNomineeHandler with required dependencies. */
    public InviteNomineeHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, SnsClient snsClient) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.snsClient = snsClient;
    }

    /** POST /auth/nominee/invite — creates an invite record and sends the deep-link SMS. */
    @PostMapping("/invite")
    public ResponseEntity<ApiResponse<NomineeInviteResponse>> inviteNominee(
            @RequestBody @Valid InviteNomineeRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        String creatorId = jwt.sub();

        List<User> userRows = dbClient.query(SELECT_USER, USER_MAPPER, creatorId);
        if (userRows.isEmpty()) {
            throw AppException.notFound("user");
        }
        User creator = userRows.get(0);
        if (creator.status() != UserStatus.ACTIVE) {
            throw AppException.forbidden();
        }
        String creatorFullName = creator.fullName();

        long nomineeCount = queryCount(creatorId);
        if (nomineeCount >= INVITE_WARN_THRESHOLD) {
            log.warn("Creator {} already has {} active nominees", creatorId, nomineeCount);
        }
        int registrationOrder = (int) nomineeCount + 1;

        String rawToken = CsprngUtil.randomHex(32);
        String tokenHash = Sha256Util.hashHex(rawToken);
        Instant now = Instant.now();
        Instant expiresAt = now.plus(INVITE_DAYS, ChronoUnit.DAYS);

        String nomineeId = CsprngUtil.randomUlid();
        dbClient.execute(INSERT_NOMINEE,
                nomineeId, creatorId, request.fullName(), request.mobile(),
                request.email(), request.relationship(), registrationOrder,
                tokenHash, expiresAt, now, now);

        sendInviteSms(nomineeId, rawToken, creatorFullName, request.mobile());

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_INVITED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(nomineeId).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(
                ApiResponse.ok(new NomineeInviteResponse(nomineeId, expiresAt), requestId));
    }

    private long queryCount(String creatorId) {
        RowMapper<Long> countMapper = (rs, row) -> rs.getLong(1);
        List<Long> rows = dbClient.query(COUNT_NOMINEES, countMapper, creatorId);
        return rows.isEmpty() ? 0L : rows.get(0);
    }

    private void sendInviteSms(String nomineeId, String rawToken, String creatorFullName, String mobile) {
        String deepLink = "https://app.deathtrap.in/nominee/register?token=" + rawToken;
        String message = String.format(
                "DeathTrap: %s has nominated you as a beneficiary. " +
                "Accept here: %s Expires in 7 days. Do not share this link.",
                creatorFullName, deepLink);

        if (snsOtpArn == null || snsOtpArn.isBlank()) {
            if (!"production".equalsIgnoreCase(environment)) {
                log.warn("[DEV-INVITE] nominee_id={} raw_token={}", nomineeId, rawToken);
            } else {
                log.warn("[DEV-INVITE] nominee_id={} (token suppressed in production)", nomineeId);
            }
            return;
        }
        try {
            snsClient.publish(b -> b.phoneNumber(mobile).message(message));
            log.info("Invite SMS sent for nomineeId={}", nomineeId);
        } catch (Exception e) {
            log.error("Failed to send invite SMS: nomineeId={} error={}", nomineeId, e.getMessage(), e);
        }
    }
}
