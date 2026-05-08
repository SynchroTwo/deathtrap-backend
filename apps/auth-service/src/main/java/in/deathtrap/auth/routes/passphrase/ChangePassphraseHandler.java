package in.deathtrap.auth.routes.passphrase;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.HibpClient;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.ChangePassphraseRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.PassphraseChangeResponse;
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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles passphrase (keypair) rotation for any authenticated party. */
@RestController
@RequestMapping("/auth/passphrase")
public class ChangePassphraseHandler {

    private static final Logger log = LoggerFactory.getLogger(ChangePassphraseHandler.class);
    private static final String PUBKEY_HEADER = "-----BEGIN PUBLIC KEY-----";

    private static final String SELECT_OTP_VERIFIED =
            "SELECT COUNT(*) FROM otp_log WHERE party_id = ? AND purpose = 'passphrase_change'::otp_purpose_enum " +
            "AND verified = true AND created_at > NOW() - INTERVAL '15 minutes'";
    private static final String RETIRE_ACTIVE_PUBKEY =
            "UPDATE party_public_keys SET is_active = false, superseded_at = ? " +
            "WHERE party_id = ? AND party_type = ?::party_type_enum AND is_active = true";
    private static final String RETIRE_ACTIVE_PRIVKEY =
            "UPDATE encrypted_privkey_blobs SET is_active = false, superseded_at = ? " +
            "WHERE party_id = ? AND party_type = ?::party_type_enum AND is_active = true";
    private static final String SELECT_MAX_VERSION =
            "SELECT COALESCE(MAX(version), 0) FROM party_public_keys " +
            "WHERE party_id = ? AND party_type = ?::party_type_enum";
    private static final String INSERT_PUBKEY =
            "INSERT INTO party_public_keys (pubkey_id, party_id, party_type, key_type, public_key_pem, " +
            "key_fingerprint, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, ?::party_type_enum, 'ecdh_p256'::key_type_enum, ?, ?, ?, true, ?, ?)";
    private static final String INSERT_PRIVKEY_BLOB =
            "INSERT INTO encrypted_privkey_blobs (privkey_blob_id, party_id, party_type, pubkey_id, " +
            "ciphertext_b64, nonce_b64, auth_tag_b64, schema_version, version, is_active, activated_at, created_at) " +
            "VALUES (?, ?, ?::party_type_enum, ?, ?, ?, ?, 1, ?, true, ?, ?)";
    private static final String SELECT_ACTIVE_SESSIONS =
            "SELECT session_id, jwt_jti, expires_at FROM sessions " +
            "WHERE party_id = ? AND party_type = ?::party_type_enum " +
            "AND revoked_at IS NULL AND session_id != ?";
    private static final String REVOKE_SESSION =
            "UPDATE sessions SET revoked_at = ? WHERE session_id = ?";
    private static final String INSERT_REVOKED_TOKEN =
            "INSERT INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?) " +
            "ON CONFLICT (jti) DO NOTHING";
    private static final String SELECT_NOMINEE_CREATOR =
            "SELECT creator_id FROM nominees WHERE nominee_id = ? LIMIT 1";

    private static final RowMapper<Long> COUNT_MAPPER = (rs, row) -> rs.getLong(1);
    private static final RowMapper<String[]> SESSION_MAPPER = (rs, row) -> new String[]{
            rs.getString("session_id"),
            rs.getString("jwt_jti"),
            rs.getTimestamp("expires_at").toInstant().toString()
    };
    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final BlobRebuildNotifier blobRebuildNotifier;
    private final HibpClient hibpClient;

    /** Constructs ChangePassphraseHandler with required dependencies. */
    public ChangePassphraseHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, BlobRebuildNotifier blobRebuildNotifier, HibpClient hibpClient) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.blobRebuildNotifier = blobRebuildNotifier;
        this.hibpClient = hibpClient;
    }

    /** POST /auth/passphrase/change — rotates keypair and revokes all other sessions. */
    @PostMapping("/change")
    public ResponseEntity<ApiResponse<PassphraseChangeResponse>> changePassphrase(
            @RequestBody @Valid ChangePassphraseRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();
        String currentSessionId = jwt.jti();

        if (partyType != PartyType.CREATOR && partyType != PartyType.NOMINEE && partyType != PartyType.LAWYER) {
            throw AppException.forbidden();
        }

        if (!otpVerified(partyId)) {
            throw new AppException(ErrorCode.AUTH_SESSION_INVALID,
                    "OTP verification required before passphrase change");
        }

        hibpClient.checkPassphrase(request.hibpPrefix(), request.hibpSuffix(),
                request.hibpCheckResult() != null && request.hibpCheckResult());

        validateRequest(request);

        Instant now = Instant.now();
        String partyTypeLower = partyType.name().toLowerCase();

        int[] sessionCount = {0};
        int[] newVersion = {1};

        String pubkeyId = CsprngUtil.randomUlid();
        String privkeyBlobId = CsprngUtil.randomUlid();

        dbClient.withTransaction(status -> {
            dbClient.execute(RETIRE_ACTIVE_PUBKEY, now, partyId, partyTypeLower);
            dbClient.execute(RETIRE_ACTIVE_PRIVKEY, now, partyId, partyTypeLower);

            List<Long> maxVersionRows = dbClient.query(SELECT_MAX_VERSION, COUNT_MAPPER, partyId, partyTypeLower);
            int maxVersion = maxVersionRows.isEmpty() ? 0 : maxVersionRows.get(0).intValue();
            newVersion[0] = maxVersion + 1;

            dbClient.execute(INSERT_PUBKEY, pubkeyId, partyId, partyTypeLower,
                    request.newPublicKeyPem(), request.newKeyFingerprint(), newVersion[0], now, now);
            dbClient.execute(INSERT_PRIVKEY_BLOB, privkeyBlobId, partyId, partyTypeLower, pubkeyId,
                    request.newEncryptedPrivkeyB64(), request.newNonceB64(), request.newAuthTagB64(),
                    newVersion[0], now, now);

            List<String[]> otherSessions = dbClient.query(SELECT_ACTIVE_SESSIONS,
                    SESSION_MAPPER, partyId, partyTypeLower, currentSessionId);
            sessionCount[0] = otherSessions.size();

            for (String[] session : otherSessions) {
                String sessionId = session[0];
                String jti = session[1];
                Instant expiresAt = Instant.parse(session[2]);
                dbClient.execute(REVOKE_SESSION, now, sessionId);
                dbClient.execute(INSERT_REVOKED_TOKEN, jti, now, expiresAt);
            }
            return null;
        });

        notifyBlobRebuild(partyId, partyType, partyTypeLower);

        auditWriter.write(AuditWritePayload.builder(AuditEventType.PASSPHRASE_CHANGED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).sessionId(currentSessionId)
                .metadataJson(Map.of("sessionsRevoked", sessionCount[0], "newKeyVersion", newVersion[0]))
                .build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new PassphraseChangeResponse("Passphrase changed successfully", newVersion[0]), requestId));
    }

    private void notifyBlobRebuild(String partyId, PartyType partyType, String partyTypeLower) {
        if (partyType == PartyType.CREATOR) {
            blobRebuildNotifier.notifyRebuildRequired(partyId, "PASSPHRASE_CHANGED", partyId, partyTypeLower);
        } else if (partyType == PartyType.NOMINEE) {
            List<String> creators = dbClient.query(SELECT_NOMINEE_CREATOR, STRING_MAPPER, partyId);
            if (!creators.isEmpty()) {
                blobRebuildNotifier.notifyRebuildRequired(
                        creators.get(0), "PASSPHRASE_CHANGED", partyId, partyTypeLower);
            }
        } else if (partyType == PartyType.LAWYER) {
            // No active recovery blobs exist yet in Sprint 3 — skip rebuild notification for lawyers.
            log.info("Passphrase changed for lawyer={} — blob rebuild skipped (no active blobs)", partyId);
        }
    }

    private boolean otpVerified(String partyId) {
        List<Long> rows = dbClient.query(SELECT_OTP_VERIFIED, COUNT_MAPPER, partyId);
        return !rows.isEmpty() && rows.get(0) > 0;
    }

    private void validateRequest(ChangePassphraseRequest request) {
        if (request.newPublicKeyPem() == null || !request.newPublicKeyPem().startsWith(PUBKEY_HEADER)) {
            throw AppException.validationFailed(
                    Map.of("newPublicKeyPem", "Must start with: " + PUBKEY_HEADER));
        }
    }
}
