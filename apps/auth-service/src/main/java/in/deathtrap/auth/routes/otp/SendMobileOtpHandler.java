package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.SendMobileOtpRequest;
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

/** Handles mobile (SMS) OTP issuance requests. */
@RestController
@RequestMapping("/auth/otp")
public class SendMobileOtpHandler {

    private static final Logger log = LoggerFactory.getLogger(SendMobileOtpHandler.class);
    private static final Pattern E164_INDIA = Pattern.compile("^\\+91[6-9]\\d{9}$");
    private static final int OTP_EXPIRY_SECONDS = 600;
    private static final int OTP_DIGITS = 1_000_000;

    private static final String SELECT_LOCKED_OTP =
            "SELECT locked_until FROM otp_log WHERE party_id = ? AND locked_until > NOW() LIMIT 1";
    private static final String INSERT_OTP =
            "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, 'sms'::otp_channel_enum, ?::otp_purpose_enum, ?, 0, false, ?, ?)";

    private static final RowMapper<Instant> INSTANT_MAPPER = (rs, row) -> rs.getTimestamp(1).toInstant();

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    /** Constructs SendMobileOtpHandler with required dependencies. */
    public SendMobileOtpHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/otp/send-mobile — generates and stores a 6-digit SHA-256-hashed SMS OTP. */
    @PostMapping("/send-mobile")
    public ResponseEntity<ApiResponse<Map<String, Object>>> sendMobileOtp(
            @RequestBody @Valid SendMobileOtpRequest request) {

        if (!E164_INDIA.matcher(request.mobile()).matches()) {
            throw AppException.validationFailed(Map.of("mobile", "Must be E.164 format: +91XXXXXXXXXX"));
        }

        String partyId = request.mobile();
        String purpose = request.purpose().name().toLowerCase();
        Instant now = Instant.now();

        Optional<Instant> lockedUntil = dbClient.queryOne(SELECT_LOCKED_OTP, INSTANT_MAPPER, partyId);
        if (lockedUntil.isPresent()) {
            throw AppException.otpLocked(lockedUntil.get());
        }

        insertOtp(partyId, purpose, now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_ISSUED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of("message", "OTP sent", "channel", "sms", "expiresIn", OTP_EXPIRY_SECONDS);
        return ResponseEntity.ok(ApiResponse.ok(body, requestId));
    }

    private void insertOtp(String partyId, String purpose, Instant now) {
        byte[] randBytes = CsprngUtil.randomBytes(4);
        int value = ((randBytes[0] & 0xFF) << 24 | (randBytes[1] & 0xFF) << 16
                | (randBytes[2] & 0xFF) << 8 | (randBytes[3] & 0xFF)) & Integer.MAX_VALUE;
        String otp = String.format("%06d", value % OTP_DIGITS);
        String otpHash = Sha256Util.hashHex(otp);
        String otpId = CsprngUtil.randomUlid();
        Instant expiresAt = now.plusSeconds(OTP_EXPIRY_SECONDS);
        dbClient.execute(INSERT_OTP, otpId, partyId, purpose, otpHash, expiresAt, now);
        log.info("[DEV-OTP] SMS OTP for party={}: {}", partyId, otp);
    }
}
