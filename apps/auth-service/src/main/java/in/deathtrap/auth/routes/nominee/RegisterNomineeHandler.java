package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.Nominee;
import in.deathtrap.common.types.dto.NomineeRegisterResponse;
import in.deathtrap.common.types.dto.RegisterNomineeRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.NomineeStatus;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

/** Handles nominee self-registration using an invite token. */
@RestController
@RequestMapping("/auth/nominee")
public class RegisterNomineeHandler {

    private static final Logger log = LoggerFactory.getLogger(RegisterNomineeHandler.class);
    private static final long SESSION_DAYS = 7L;
    private static final int INVITE_TOKEN_HEX_LENGTH = 64;
    private static final int SALT_HEX_LENGTH = 64;
    private static final String PUBKEY_HEADER = "-----BEGIN PUBLIC KEY-----";

    private static final String SELECT_NOMINEE_BY_TOKEN =
            "SELECT nominee_id, creator_id, full_name, mobile, email, relationship, registration_order, " +
            "invite_token_hash, invite_expires_at, status, fingerprint_verified, fingerprint_verified_at, " +
            "created_at, updated_at " +
            "FROM nominees WHERE invite_token_hash = ? LIMIT 1";
    private static final String SELECT_OTP_VERIFIED =
            "SELECT COUNT(*) FROM otp_log WHERE party_id = ? AND purpose = 'registration'::otp_purpose_enum " +
            "AND verified = true AND created_at > NOW() - INTERVAL '15 minutes'";
    private static final String INSERT_SALT =
            "INSERT INTO party_salts (salt_id, party_id, party_type, salt_hex, schema_version, created_at) " +
            "VALUES (?, ?, 'nominee'::party_type_enum, ?, 1, ?)";
    private static final String INSERT_PUBKEY =
            "INSERT INTO party_public_keys (pubkey_id, party_id, party_type, key_type, public_key_pem, " +
            "key_fingerprint, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'nominee'::party_type_enum, 'ecdh_p256'::key_type_enum, ?, ?, 1, true, ?, ?)";
    private static final String INSERT_PRIVKEY_BLOB =
            "INSERT INTO encrypted_privkey_blobs (privkey_blob_id, party_id, party_type, pubkey_id, " +
            "ciphertext_b64, nonce_b64, auth_tag_b64, schema_version, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, 'nominee'::party_type_enum, ?, ?, ?, ?, 1, 1, true, ?, ?)";
    private static final String UPDATE_NOMINEE_ACTIVE =
            "UPDATE nominees SET status = 'active'::nominee_status_enum, invite_token_hash = NULL, " +
            "invite_expires_at = NULL, updated_at = ? WHERE nominee_id = ?";
    private static final String INSERT_SESSION =
            "INSERT INTO sessions (session_id, party_id, party_type, jwt_jti, expires_at, created_at) " +
            "VALUES (?, ?, 'nominee'::party_type_enum, ?, ?, ?)";

    private static final RowMapper<Nominee> NOMINEE_MAPPER = (rs, row) -> new Nominee(
            rs.getString("nominee_id"),
            rs.getString("creator_id"),
            rs.getString("full_name"),
            rs.getString("mobile"),
            rs.getString("email"),
            rs.getString("relationship"),
            rs.getInt("registration_order"),
            rs.getString("invite_token_hash"),
            rs.getTimestamp("invite_expires_at") != null ? rs.getTimestamp("invite_expires_at").toInstant() : null,
            NomineeStatus.valueOf(rs.getString("status").toUpperCase()),
            rs.getBoolean("fingerprint_verified"),
            rs.getTimestamp("fingerprint_verified_at") != null ? rs.getTimestamp("fingerprint_verified_at").toInstant() : null,
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final BlobRebuildNotifier blobRebuildNotifier;

    /** Constructs RegisterNomineeHandler with required dependencies. */
    public RegisterNomineeHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, BlobRebuildNotifier blobRebuildNotifier) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.blobRebuildNotifier = blobRebuildNotifier;
    }

    /** POST /auth/nominee/register — validates invite token, stores crypto records, issues JWT. */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<NomineeRegisterResponse>> registerNominee(
            @RequestBody @Valid RegisterNomineeRequest request) {

        validateRequest(request);

        String tokenHash = Sha256Util.hashHex(request.inviteToken());
        List<Nominee> nomineeRows = dbClient.query(SELECT_NOMINEE_BY_TOKEN, NOMINEE_MAPPER, tokenHash);
        if (nomineeRows.isEmpty()) {
            throw AppException.inviteInvalid();
        }
        Nominee nominee = nomineeRows.get(0);

        Instant now = Instant.now();
        if (nominee.inviteExpiresAt() == null || nominee.inviteExpiresAt().isBefore(now)) {
            throw AppException.inviteExpired();
        }
        if (nominee.status() != NomineeStatus.INVITED) {
            throw AppException.conflict("Nominee already registered");
        }

        if (!otpVerified(nominee.nomineeId())) {
            throw new AppException(ErrorCode.AUTH_SESSION_INVALID, "OTP verification required before registration");
        }

        String saltId = CsprngUtil.randomUlid();
        String pubkeyId = CsprngUtil.randomUlid();
        String privkeyBlobId = CsprngUtil.randomUlid();

        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_SALT, saltId, nominee.nomineeId(), request.saltHex(), now);
            dbClient.execute(INSERT_PUBKEY, pubkeyId, nominee.nomineeId(),
                    request.publicKeyPem(), request.keyFingerprint(), now, now);
            dbClient.execute(INSERT_PRIVKEY_BLOB, privkeyBlobId, nominee.nomineeId(), pubkeyId,
                    request.encryptedPrivkeyB64(), request.nonceB64(), request.authTagB64(), now, now);
            dbClient.execute(UPDATE_NOMINEE_ACTIVE, now, nominee.nomineeId());
            return null;
        });

        String sessionId = CsprngUtil.randomUlid();
        Instant expiresAt = now.plus(SESSION_DAYS, ChronoUnit.DAYS);
        String jwt = jwtService.issueToken(nominee.nomineeId(), PartyType.NOMINEE, sessionId);
        dbClient.execute(INSERT_SESSION, sessionId, nominee.nomineeId(), sessionId, expiresAt, now);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_REGISTERED, AuditResult.SUCCESS)
                .actorId(nominee.nomineeId()).actorType(PartyType.NOMINEE)
                .targetId(nominee.creatorId()).build());

        blobRebuildNotifier.notifyRebuildRequired(
                nominee.creatorId(), "NOMINEE_REGISTERED", nominee.nomineeId(), "nominee");

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new NomineeRegisterResponse(nominee.nomineeId(), jwt, sessionId, expiresAt), requestId));
    }

    private boolean otpVerified(String nomineeId) {
        RowMapper<Long> countMapper = (rs, row) -> rs.getLong(1);
        List<Long> rows = dbClient.query(SELECT_OTP_VERIFIED, countMapper, nomineeId);
        return !rows.isEmpty() && rows.get(0) > 0;
    }

    private void validateRequest(RegisterNomineeRequest request) {
        if (request.inviteToken() == null || request.inviteToken().length() != INVITE_TOKEN_HEX_LENGTH
                || !request.inviteToken().matches("[0-9a-fA-F]+")) {
            throw AppException.validationFailed(
                    Map.of("inviteToken", "Must be exactly 64 hex characters"));
        }
        if (request.saltHex() == null || request.saltHex().length() != SALT_HEX_LENGTH
                || !request.saltHex().matches("[0-9a-fA-F]+")) {
            throw AppException.validationFailed(
                    Map.of("saltHex", "Must be exactly 64 hex characters"));
        }
        if (request.publicKeyPem() == null || !request.publicKeyPem().startsWith(PUBKEY_HEADER)) {
            throw AppException.validationFailed(
                    Map.of("publicKeyPem", "Must start with: " + PUBKEY_HEADER));
        }
    }
}
