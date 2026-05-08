package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.LawyerRegisterResponse;
import in.deathtrap.common.types.dto.RegisterLawyerRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles lawyer self-registration with Bar Council KYC (stub). */
@RestController
@RequestMapping("/auth/lawyer")
public class RegisterLawyerHandler {

    private static final Logger log = LoggerFactory.getLogger(RegisterLawyerHandler.class);
    private static final int SALT_HEX_LENGTH = 64;
    private static final String PUBKEY_HEADER = "-----BEGIN PUBLIC KEY-----";

    private static final String SELECT_OTP_VERIFIED =
            "SELECT COUNT(*) FROM otp_log WHERE party_id = ? AND purpose = 'registration'::otp_purpose_enum " +
            "AND verified = true AND created_at > NOW() - INTERVAL '15 minutes'";
    private static final String COUNT_BY_MOBILE =
            "SELECT COUNT(*) FROM lawyers WHERE mobile = ?";
    private static final String COUNT_BY_EMAIL =
            "SELECT COUNT(*) FROM lawyers WHERE email = ?";
    private static final String COUNT_BY_ENROLLMENT =
            "SELECT COUNT(*) FROM lawyers WHERE enrollment_no = ?";
    private static final String INSERT_LAWYER =
            "INSERT INTO lawyers (lawyer_id, full_name, mobile, email, bar_council, enrollment_no, " +
            "bar_verified, kyc_admin_approved, status, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, false, false, 'pending'::lawyer_status_enum, ?, ?)";
    private static final String INSERT_KYC_FLAG =
            "INSERT INTO kyc_flags (kyc_id, party_id, party_type, kyc_type, passed, checked_at) " +
            "VALUES (?, ?, 'lawyer'::party_type_enum, 'bar_council'::kyc_type_enum, false, ?)";
    private static final String INSERT_SALT =
            "INSERT INTO party_salts (salt_id, party_id, party_type, salt_hex, schema_version, created_at) " +
            "VALUES (?, ?, 'lawyer'::party_type_enum, ?, 1, ?)";
    private static final String INSERT_PUBKEY =
            "INSERT INTO party_public_keys (pubkey_id, party_id, party_type, key_type, public_key_pem, " +
            "key_fingerprint, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'lawyer'::party_type_enum, 'ecdh_p256'::key_type_enum, ?, ?, 1, true, ?, ?)";
    private static final String INSERT_PRIVKEY_BLOB =
            "INSERT INTO encrypted_privkey_blobs (privkey_blob_id, party_id, party_type, pubkey_id, " +
            "ciphertext_b64, nonce_b64, auth_tag_b64, schema_version, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'lawyer'::party_type_enum, ?, ?, ?, ?, 1, 1, true, ?, ?)";

    private static final RowMapper<Long> COUNT_MAPPER = (rs, row) -> rs.getLong(1);

    private final DbClient dbClient;
    private final AuditWriter auditWriter;

    /** Constructs RegisterLawyerHandler with required dependencies. */
    public RegisterLawyerHandler(DbClient dbClient, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/lawyer/register — creates a pending lawyer account awaiting admin approval. */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LawyerRegisterResponse>> registerLawyer(
            @RequestBody @Valid RegisterLawyerRequest request) {

        validateRequest(request);

        if (!otpVerified(request.mobile())) {
            throw new AppException(ErrorCode.AUTH_SESSION_INVALID, "OTP verification required before registration");
        }

        checkUniqueness(request);

        // SECURITY-STUB: Bar Council registry API not called. Real integration Sprint 9.
        log.info("[KYC-STUB] Bar Council verification skipped for mobile={}", request.mobile());

        String lawyerId = CsprngUtil.randomUlid();
        String saltId = CsprngUtil.randomUlid();
        String pubkeyId = CsprngUtil.randomUlid();
        String privkeyBlobId = CsprngUtil.randomUlid();
        String kycFlagId = CsprngUtil.randomUlid();
        Instant now = Instant.now();

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_LAWYER,
                    lawyerId, request.fullName(), request.mobile(), request.email(),
                    request.barCouncil(), request.enrollmentNo(), now, now);
            dbClient.execute(INSERT_KYC_FLAG, kycFlagId, lawyerId, now);
            dbClient.execute(INSERT_SALT, saltId, lawyerId, request.saltHex(), now);
            dbClient.execute(INSERT_PUBKEY, pubkeyId, lawyerId,
                    request.publicKeyPem(), request.keyFingerprint(), now, now);
            dbClient.execute(INSERT_PRIVKEY_BLOB, privkeyBlobId, lawyerId, pubkeyId,
                    request.encryptedPrivkeyB64(), request.nonceB64(), request.authTagB64(), now, now);
            return null;
        });

        auditWriter.write(AuditWritePayload.builder(AuditEventType.LAWYER_REGISTERED, AuditResult.SUCCESS)
                .actorId(lawyerId).actorType(PartyType.LAWYER).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(new LawyerRegisterResponse(
                lawyerId, "pending",
                "Registration received. Awaiting admin approval before activation."), requestId));
    }

    private boolean otpVerified(String mobile) {
        List<Long> rows = dbClient.query(SELECT_OTP_VERIFIED, COUNT_MAPPER, mobile);
        return !rows.isEmpty() && rows.get(0) > 0;
    }

    private void checkUniqueness(RegisterLawyerRequest request) {
        List<Long> byMobile = dbClient.query(COUNT_BY_MOBILE, COUNT_MAPPER, request.mobile());
        if (!byMobile.isEmpty() && byMobile.get(0) > 0) {
            throw AppException.registrationDuplicate("mobile");
        }
        List<Long> byEmail = dbClient.query(COUNT_BY_EMAIL, COUNT_MAPPER, request.email());
        if (!byEmail.isEmpty() && byEmail.get(0) > 0) {
            throw AppException.registrationDuplicate("email");
        }
        List<Long> byEnrollment = dbClient.query(COUNT_BY_ENROLLMENT, COUNT_MAPPER, request.enrollmentNo());
        if (!byEnrollment.isEmpty() && byEnrollment.get(0) > 0) {
            throw AppException.registrationDuplicate("enrollmentNo");
        }
    }

    private void validateRequest(RegisterLawyerRequest request) {
        if (request.saltHex() == null || request.saltHex().length() != SALT_HEX_LENGTH
                || !request.saltHex().matches("[0-9a-fA-F]+")) {
            throw AppException.validationFailed(Map.of("saltHex", "Must be exactly 64 hex characters"));
        }
        if (request.publicKeyPem() == null || !request.publicKeyPem().startsWith(PUBKEY_HEADER)) {
            throw AppException.validationFailed(
                    Map.of("publicKeyPem", "Must start with: " + PUBKEY_HEADER));
        }
    }
}
