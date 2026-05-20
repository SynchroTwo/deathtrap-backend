package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.service.BlobRebuildNotifier;
import in.deathtrap.auth.service.InviteTokenVerifier;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.AcceptInviteRequest;
import in.deathtrap.common.types.dto.AcceptInviteResponse;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Path-A nominee accept ({@code POST /auth/nominee/accept}, unauthenticated).
 *
 * <p>The creator-signed invite token authenticates the request: the backend resolves the
 * creator named in the token, loads that creator's active pubkey, and verifies the token's
 * ECDSA signature (see {@link InviteTokenVerifier}). On success the nominee's freshly
 * generated crypto material is stored and a session is issued — the nominee is logged in
 * immediately, mirroring creator registration.
 */
@RestController
@RequestMapping("/auth/nominee")
public class NomineeAcceptHandler {

    private static final String PUBKEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final Pattern PEM_HEADERS = Pattern.compile(
            "-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+");

    private static final String SELECT_CREATOR_PUBKEY =
            "SELECT public_key_pem FROM party_public_keys " +
            "WHERE party_id = ? AND party_type = 'creator'::party_type_enum AND is_active = true LIMIT 1";
    private static final String SELECT_NOMINEE_STATUS =
            "SELECT status::text FROM nominees WHERE nominee_id = ? AND creator_id = ? LIMIT 1";
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
    private static final String UPDATE_NOMINEE_REGISTERED =
            "UPDATE nominees SET status = 'active'::nominee_status_enum, registered_at = ?, " +
            "invite_payload_hash = ?, invite_token_hash = NULL, invite_expires_at = NULL, updated_at = ? " +
            "WHERE nominee_id = ? AND creator_id = ? AND status = 'invited'::nominee_status_enum";
    private static final String INSERT_SESSION =
            "INSERT INTO sessions (session_id, party_id, party_type, jwt_jti, expires_at, created_at) " +
            "VALUES (?, ?, 'nominee'::party_type_enum, ?, ?, ?)";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final BlobRebuildNotifier blobRebuildNotifier;

    /** Constructs NomineeAcceptHandler with required dependencies. */
    public NomineeAcceptHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, BlobRebuildNotifier blobRebuildNotifier) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.blobRebuildNotifier = blobRebuildNotifier;
    }

    /** POST /auth/nominee/accept — verifies the signed invite, stores nominee crypto, issues a session. */
    @PostMapping("/accept")
    public ResponseEntity<ApiResponse<AcceptInviteResponse>> accept(
            @RequestBody @Valid AcceptInviteRequest request) {

        validatePubkey(request.pubkeyPem());
        String saltHex = saltB64ToHex(request.saltB64());

        String creatorId = InviteTokenVerifier.peekCreatorId(request.inviteToken());
        String creatorPubkeyPem = dbClient.queryOne(SELECT_CREATOR_PUBKEY, STRING_MAPPER, creatorId)
                .orElseThrow(AppException::inviteInvalid);

        InviteTokenVerifier.ParsedInvite invite =
                InviteTokenVerifier.verify(request.inviteToken(), creatorPubkeyPem);

        String nomineeId = invite.nomineeId();
        if (nomineeId == null || nomineeId.isBlank()) {
            throw AppException.inviteInvalid();
        }

        Optional<String> currentStatus = dbClient.queryOne(
                SELECT_NOMINEE_STATUS, STRING_MAPPER, nomineeId, creatorId);
        if (currentStatus.isEmpty()) {
            throw AppException.nomineeNotFound();
        }
        if (!"invited".equals(currentStatus.get())) {
            throw AppException.nomineeAlreadyRegistered();
        }

        Instant now = Instant.now();
        String payloadHash = Sha256Util.hashHex(invite.payloadBytes());
        String fingerprint = fingerprintFromPem(request.pubkeyPem());
        String saltId = CsprngUtil.randomUlid();
        String pubkeyId = CsprngUtil.randomUlid();
        String privkeyBlobId = CsprngUtil.randomUlid();
        String sessionId = CsprngUtil.randomUlid();

        int updated = dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_SALT, saltId, nomineeId, saltHex, Timestamp.from(now));
            dbClient.execute(INSERT_PUBKEY, pubkeyId, nomineeId, request.pubkeyPem(),
                    fingerprint, Timestamp.from(now), Timestamp.from(now));
            dbClient.execute(INSERT_PRIVKEY_BLOB, privkeyBlobId, nomineeId, pubkeyId,
                    request.encryptedPrivkeyB64(), request.encryptedPrivkeyNonceB64(),
                    request.encryptedPrivkeyTagB64(), Timestamp.from(now), Timestamp.from(now));
            int rows = dbClient.execute(UPDATE_NOMINEE_REGISTERED, Timestamp.from(now),
                    payloadHash, Timestamp.from(now), nomineeId, creatorId);
            dbClient.execute(INSERT_SESSION, sessionId, nomineeId, sessionId,
                    Timestamp.from(now.plusSeconds(jwtService.getAccessTokenSeconds())), Timestamp.from(now));
            return rows;
        });
        // Lost the race: another accept flipped status between the pre-check and the UPDATE.
        if (updated == 0) {
            throw AppException.nomineeAlreadyRegistered();
        }

        String sessionJwt = jwtService.issueToken(nomineeId, PartyType.NOMINEE, sessionId);
        String refreshToken = jwtService.issueRefreshToken(nomineeId, PartyType.NOMINEE, sessionId);
        Instant accessExpiresAt = now.plusSeconds(jwtService.getAccessTokenSeconds());

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_REGISTERED, AuditResult.SUCCESS)
                .actorId(nomineeId).actorType(PartyType.NOMINEE).targetId(creatorId).build());
        auditWriter.write(AuditWritePayload.builder(AuditEventType.SESSION_CREATED, AuditResult.SUCCESS)
                .actorId(nomineeId).actorType(PartyType.NOMINEE).sessionId(sessionId).build());

        blobRebuildNotifier.notifyRebuildRequired(creatorId, "NOMINEE_REGISTERED", nomineeId, "nominee");

        AcceptInviteResponse body = new AcceptInviteResponse(
                nomineeId, creatorId, PartyType.NOMINEE.name().toLowerCase(),
                sessionJwt, refreshToken, accessExpiresAt.toString());
        return ResponseEntity.status(201).body(ApiResponse.ok(body, UUID.randomUUID().toString()));
    }

    private static void validatePubkey(String pem) {
        if (pem == null || !pem.startsWith(PUBKEY_HEADER)) {
            throw AppException.validationFailed(Map.of("pubkeyPem", "Must start with: " + PUBKEY_HEADER));
        }
    }

    private static String saltB64ToHex(String saltB64) {
        try {
            return HexFormat.of().formatHex(Base64.getDecoder().decode(saltB64));
        } catch (IllegalArgumentException ex) {
            throw AppException.validationFailed(Map.of("saltB64", "Must be valid base64"));
        }
    }

    private static String fingerprintFromPem(String pem) {
        byte[] der = Base64.getDecoder().decode(PEM_HEADERS.matcher(pem).replaceAll(""));
        return Sha256Util.hashHex(der);
    }
}
