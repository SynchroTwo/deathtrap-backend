package in.deathtrap.auth.routes.otp;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.SendEmailOtpRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.OtpPurpose;
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

/** Handles email OTP issuance requests. Only REGISTRATION purpose uses email OTP currently. */
@RestController
@RequestMapping("/auth/otp")
public class SendEmailOtpHandler {

    private static final Logger log = LoggerFactory.getLogger(SendEmailOtpHandler.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final int OTP_EXPIRY_SECONDS = 600;
    private static final int OTP_DIGITS = 1_000_000;

    private static final String INSERT_OTP =
            "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, attempts, verified, expires_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, 'email'::otp_channel_enum, ?::otp_purpose_enum, ?, 0, false, ?, ?)";

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    /** Constructs SendEmailOtpHandler with required dependencies. */
    public SendEmailOtpHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/otp/send-email — generates and stores a 6-digit SHA-256-hashed email OTP.
     *  partyId in otp_log is the email address so verify-email can look it up. */
    @PostMapping("/send-email")
    public ResponseEntity<ApiResponse<Map<String, Object>>> sendEmailOtp(
            @RequestBody @Valid SendEmailOtpRequest request) {

        if (!EMAIL_PATTERN.matcher(request.email()).matches()) {
            throw AppException.validationFailed(Map.of("email", "Invalid email format"));
        }
        if (request.purpose() != OtpPurpose.REGISTRATION) {
            throw AppException.validationFailed(
                    Map.of("purpose", "Email OTP is only supported for REGISTRATION"));
        }

        String partyId = request.email();
        String purpose = request.purpose().name().toLowerCase();
        Instant now = Instant.now();

        insertOtp(partyId, purpose, now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.OTP_ISSUED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(PartyType.CREATOR).build());

        String requestId = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of("message", "OTP sent", "channel", "email", "expiresIn", OTP_EXPIRY_SECONDS);
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
        log.info("[DEV-OTP] EMAIL OTP for party={}: {}", partyId, otp);
    }
}
