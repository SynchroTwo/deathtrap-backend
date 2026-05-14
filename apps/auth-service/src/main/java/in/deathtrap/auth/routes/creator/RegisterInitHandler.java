package in.deathtrap.auth.routes.creator;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.RegisterInitRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Initiates a creator registration by validating mobile+email and sending OTPs
 *  to both channels in a single server-side call. The client follows up with
 *  /auth/otp/verify-mobile + /auth/otp/verify-email and then /auth/register. */
@RestController
@RequestMapping("/auth/register")
public class RegisterInitHandler {

    private static final Logger log = LoggerFactory.getLogger(RegisterInitHandler.class);
    private static final Pattern E164_INDIA = Pattern.compile("^\\+91[6-9]\\d{9}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final int OTP_EXPIRY_SECONDS = 600;
    private static final int OTP_DIGITS = 1_000_000;
    private static final String PURPOSE = "registration";

    private static final String SELECT_BY_MOBILE =
            "SELECT user_id FROM users WHERE mobile = ? AND deleted_at IS NULL LIMIT 1";
    private static final String SELECT_BY_EMAIL =
            "SELECT user_id FROM users WHERE email = ? AND deleted_at IS NULL LIMIT 1";
    private static final String SELECT_LOCKED_OTP =
            "SELECT locked_until FROM otp_log WHERE party_id = ? AND locked_until > NOW() LIMIT 1";
    private static final String INSERT_OTP =
            "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?::otp_channel_enum, 'registration'::otp_purpose_enum, ?, 0, false, ?, ?)";

    private static final RowMapper<String> ID_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Instant> INSTANT_MAPPER = (rs, row) -> rs.getTimestamp(1).toInstant();

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    public RegisterInitHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/register/init — validates mobile+email and sends OTPs to both. */
    @PostMapping("/init")
    public ResponseEntity<ApiResponse<Map<String, Object>>> init(
            @RequestBody @Valid RegisterInitRequest request) {

        if (!E164_INDIA.matcher(request.mobile()).matches()) {
            throw AppException.validationFailed(Map.of("mobile", "Must be E.164 format: +91XXXXXXXXXX"));
        }
        if (!EMAIL_PATTERN.matcher(request.email()).matches()) {
            throw AppException.validationFailed(Map.of("email", "Invalid email format"));
        }

        Optional<String> existingByMobile = dbClient.queryOne(SELECT_BY_MOBILE, ID_MAPPER, request.mobile());
        if (existingByMobile.isPresent()) {
            throw AppException.registrationDuplicate("mobile");
        }
        Optional<String> existingByEmail = dbClient.queryOne(SELECT_BY_EMAIL, ID_MAPPER, request.email());
        if (existingByEmail.isPresent()) {
            throw AppException.registrationDuplicate("email");
        }

        Optional<Instant> mobileLocked = dbClient.queryOne(SELECT_LOCKED_OTP, INSTANT_MAPPER, request.mobile());
        if (mobileLocked.isPresent()) {
            throw AppException.otpLocked(mobileLocked.get());
        }
        Optional<Instant> emailLocked = dbClient.queryOne(SELECT_LOCKED_OTP, INSTANT_MAPPER, request.email());
        if (emailLocked.isPresent()) {
            throw AppException.otpLocked(emailLocked.get());
        }

        Instant now = Instant.now();
        issueOtp(request.mobile(), "sms", now);
        issueOtp(request.email(), "email", now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_ISSUED, AuditResult.SUCCESS)
                .actorId(request.mobile()).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of(
                "message", "OTPs sent to mobile and email. Verify both to complete registration.",
                "channels", new String[]{"sms", "email"},
                "expiresIn", OTP_EXPIRY_SECONDS);
        return ResponseEntity.accepted().body(ApiResponse.ok(body, requestId));
    }

    private void issueOtp(String partyId, String channel, Instant now) {
        byte[] randBytes = CsprngUtil.randomBytes(4);
        int value = ((randBytes[0] & 0xFF) << 24 | (randBytes[1] & 0xFF) << 16
                | (randBytes[2] & 0xFF) << 8 | (randBytes[3] & 0xFF)) & Integer.MAX_VALUE;
        String otp = String.format("%06d", value % OTP_DIGITS);
        String otpHash = Sha256Util.hashHex(otp);
        String otpId = CsprngUtil.randomUlid();
        Instant expiresAt = now.plusSeconds(OTP_EXPIRY_SECONDS);
        dbClient.execute(INSERT_OTP, otpId, partyId, channel, otpHash, expiresAt, now);
        log.info("[DEV-OTP] {} OTP for party={}: {}", channel.toUpperCase(), partyId, otp);
    }
}
