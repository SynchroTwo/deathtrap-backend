package in.deathtrap.auth.routes.creator;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.RegisterCreatorRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles creator registration. */
@RestController
@RequestMapping("/auth")
public class RegisterHandler {

    private static final Logger log = LoggerFactory.getLogger(RegisterHandler.class);
    private static final Set<Integer> VALID_INACTIVITY_MONTHS = Set.of(6, 12, 24, 36);
    private static final String PUBKEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final int SALT_HEX_LENGTH = 64;
    private static final int MIN_ENTROPY_BITS = 60;

    private static final String SELECT_BY_MOBILE =
            "SELECT user_id FROM users WHERE mobile = ? AND deleted_at IS NULL LIMIT 1";
    private static final String SELECT_BY_EMAIL =
            "SELECT user_id FROM users WHERE email = ? AND deleted_at IS NULL LIMIT 1";
    private static final String INSERT_USER =
            "INSERT INTO users (user_id, full_name, date_of_birth, mobile, email, address, aadhaar_ref, " +
            "kyc_status, status, inactivity_trigger_months, locker_completeness_pct, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending'::kyc_status_enum, 'active'::user_status_enum, ?, 0, ?, ?)";
    private static final String INSERT_SALT =
            "INSERT INTO party_salts (salt_id, party_id, party_type, salt_hex, schema_version, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?, ?, ?)";
    private static final String INSERT_PUBKEY =
            "INSERT INTO party_public_keys (pubkey_id, party_id, party_type, key_type, public_key_pem, " +
            "key_fingerprint, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, 'ecdh_p256'::key_type_enum, ?, ?, 1, true, ?, ?)";
    private static final String INSERT_PRIVKEY_BLOB =
            "INSERT INTO encrypted_privkey_blobs (privkey_blob_id, party_id, party_type, pubkey_id, " +
            "ciphertext_b64, nonce_b64, auth_tag_b64, schema_version, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'creator'::party_type_enum, ?, ?, ?, ?, ?, 1, true, ?, ?)";
    private static final String INSERT_KYC_FLAG =
            "INSERT INTO kyc_flags (kyc_id, party_id, party_type, kyc_type, passed, checked_at, metadata) " +
            "VALUES (?, ?, 'creator'::party_type_enum, 'aadhaar_otp'::kyc_type_enum, true, ?, ?::jsonb)";
    private static final String UPDATE_KYC_STATUS =
            "UPDATE users SET kyc_status = 'verified'::kyc_status_enum, updated_at = ? WHERE user_id = ?";

    private static final RowMapper<String> ID_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs RegisterHandler with required dependencies. */
    public RegisterHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/register — atomically creates user + crypto records in one transaction. */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(
            @RequestBody @Valid RegisterCreatorRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        jwtService.validateVerifiedToken(authHeader.substring(7));

        if (!request.hibpCheckResult() || request.entropyBits() < MIN_ENTROPY_BITS) {
            throw AppException.passphraseCompromised();
        }

        validateRequest(request);

        Optional<String> existingByMobile = dbClient.queryOne(SELECT_BY_MOBILE, ID_MAPPER, request.mobile());
        if (existingByMobile.isPresent()) {
            throw AppException.registrationDuplicate("mobile");
        }
        Optional<String> existingByEmail = dbClient.queryOne(SELECT_BY_EMAIL, ID_MAPPER, request.email());
        if (existingByEmail.isPresent()) {
            throw AppException.registrationDuplicate("email");
        }

        String userId = CsprngUtil.randomUlid();
        String saltId = CsprngUtil.randomUlid();
        String pubkeyId = CsprngUtil.randomUlid();
        String privkeyBlobId = CsprngUtil.randomUlid();
        String kycFlagId = CsprngUtil.randomUlid();
        Instant now = Instant.now();

        // SECURITY-STUB: Aadhaar eKYC not implemented — Sprint 9 will call real UIDAI API
        String kycMetadata = String.format(
                "{\"stub\":true,\"aadhaar_ref\":\"%s\",\"kyc_provider_ref\":\"%s\"}",
                request.aadhaarRef() != null ? request.aadhaarRef() : "",
                request.kycProviderRef() != null ? request.kycProviderRef() : "");
        log.info("[KYC-STUB] Aadhaar eKYC skipped for userId={}", userId);

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_USER,
                    userId, request.fullName(), request.dateOfBirth(),
                    request.mobile(), request.email(), request.address(),
                    request.aadhaarRef(), request.inactivityTriggerMonths(), now, now);
            dbClient.execute(INSERT_SALT, saltId, userId, request.saltHex(), request.schemaVersion(), now);
            dbClient.execute(INSERT_PUBKEY, pubkeyId, userId, request.publicKeyPem(), request.keyFingerprint(), now, now);
            dbClient.execute(INSERT_PRIVKEY_BLOB, privkeyBlobId, userId, pubkeyId,
                    request.encryptedPrivkeyB64(), request.nonceB64(), request.authTagB64(),
                    request.schemaVersion(), now, now);
            dbClient.execute(INSERT_KYC_FLAG, kycFlagId, userId, now, kycMetadata);
            dbClient.execute(UPDATE_KYC_STATUS, now, userId);
            return null;
        });

        auditWriter.write(AuditWritePayload.builder(AuditEventType.USER_REGISTERED, AuditResult.SUCCESS)
                .actorId(userId).actorType(PartyType.CREATOR).targetId(userId).targetType("user").build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(Map.of("userId", userId), requestId));
    }

    private void validateRequest(RegisterCreatorRequest request) {
        if (!VALID_INACTIVITY_MONTHS.contains(request.inactivityTriggerMonths())) {
            throw AppException.validationFailed(
                    Map.of("inactivityTriggerMonths", "Must be one of: 6, 12, 24, 36"));
        }
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
