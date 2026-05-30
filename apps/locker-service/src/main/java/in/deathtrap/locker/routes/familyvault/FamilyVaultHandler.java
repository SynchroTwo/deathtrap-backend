package in.deathtrap.locker.routes.familyvault;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.FamilyVaultWrapRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.service.ClosureWriteGate;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** E011 Phase 1A — Family Vault wrap CRUD endpoints.
 *  Mounted under /locker/family-vault/* (Path A — no CDK route change).
 *  Path Y locked: nominees are read-only on the locker blob path; this
 *  service just stores/serves opaque ECDH wraps. */
@RestController
@RequestMapping("/locker/family-vault")
public class FamilyVaultHandler {

    private static final Logger log = LoggerFactory.getLogger(FamilyVaultHandler.class);

    private static final String SELECT_LOCKER_MODE =
            "SELECT recovery_mode::text FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_NOMINEE_OWNED =
            "SELECT 1 FROM nominees WHERE nominee_id = ? AND creator_id = ? " +
            "AND status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_EXISTING_ACTIVE_WRAP =
            "SELECT 1 FROM family_vault_wraps WHERE creator_id = ? " +
            "AND nominee_party_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_WRAP_OWNER =
            "SELECT creator_id, status::text FROM family_vault_wraps WHERE wrap_id = ? LIMIT 1";
    private static final String SELECT_MY_WRAPS =
            "SELECT fvw.wrap_id, fvw.creator_id, COALESCE(u.full_name, '') AS creator_display_name, " +
            "fvw.spec_version, fvw.salt_hex, fvw.key_fingerprint, fvw.eph_pubkey_b64, fvw.nonce_b64, " +
            "fvw.ciphertext_b64, fvw.auth_tag_b64, fvw.created_at " +
            "FROM family_vault_wraps fvw " +
            "JOIN users u ON u.user_id = fvw.creator_id " +
            "WHERE fvw.nominee_party_id = ? AND fvw.status = 'active' " +
            "ORDER BY fvw.created_at DESC";
    private static final String INSERT_WRAP =
            "INSERT INTO family_vault_wraps (wrap_id, creator_id, nominee_party_id, spec_version, " +
            "salt_hex, key_fingerprint, eph_pubkey_b64, nonce_b64, ciphertext_b64, auth_tag_b64, " +
            "status, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())";
    private static final String REVOKE_WRAP =
            "UPDATE family_vault_wraps SET status = 'revoked', revoked_at = NOW(), revoked_reason = ? " +
            "WHERE wrap_id = ? AND status = 'active'";

    private static final RowMapper<Integer> ONE_MAPPER = (rs, row) -> 1;
    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<WrapOwner> WRAP_OWNER_MAPPER = (rs, row) ->
            new WrapOwner(rs.getString("creator_id"), rs.getString("status"));
    private static final RowMapper<MyWrapDto> MY_WRAP_MAPPER = (rs, row) -> new MyWrapDto(
            rs.getString("wrap_id"),
            rs.getString("creator_id"),
            rs.getString("creator_display_name"),
            rs.getString("spec_version"),
            rs.getString("salt_hex"),
            rs.getString("key_fingerprint"),
            rs.getString("eph_pubkey_b64"),
            rs.getString("nonce_b64"),
            rs.getString("ciphertext_b64"),
            rs.getString("auth_tag_b64"),
            rs.getTimestamp("created_at").toInstant());

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final ClosureWriteGate closureWriteGate;

    public FamilyVaultHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter,
            ClosureWriteGate closureWriteGate) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.closureWriteGate = closureWriteGate;
    }

    /** POST /locker/family-vault/wraps — creator adds a wrap. */
    @PostMapping("/wraps")
    public ResponseEntity<ApiResponse<CreateWrapResponse>> createWrap(
            @RequestBody @Valid FamilyVaultWrapRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        closureWriteGate.assertWritesAllowed(creatorId);

        // 1. Locker must be in family_vault mode.
        String mode = dbClient.queryOne(SELECT_LOCKER_MODE, STRING_MAPPER, creatorId).orElse(null);
        if (mode == null || !"family_vault".equals(mode)) {
            throw new AppException(ErrorCode.FAMILY_VAULT_MODE_REQUIRED,
                    "Locker recovery_mode is " + mode + "; must be family_vault");
        }

        // 2. Nominee must belong to caller.
        if (dbClient.queryOne(SELECT_NOMINEE_OWNED, ONE_MAPPER, request.nomineePartyId(), creatorId).isEmpty()) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                    "Nominee is not owned by the caller or is not active");
        }

        // 3. No existing active wrap for this (creator, nominee) pair.
        if (dbClient.queryOne(SELECT_EXISTING_ACTIVE_WRAP, ONE_MAPPER, creatorId, request.nomineePartyId()).isPresent()) {
            throw new AppException(ErrorCode.FAMILY_VAULT_WRAP_ALREADY_EXISTS,
                    "Active wrap exists for this nominee; revoke first");
        }

        // 4. Insert.
        dbClient.execute(INSERT_WRAP,
                request.wrapId(), creatorId, request.nomineePartyId(),
                request.specVersion(), request.saltHex(), request.keyFingerprint(),
                request.ephPubkeyB64(), request.nonceB64(), request.ciphertextB64(), request.authTagB64());

        Instant createdAt = Instant.now();
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_WRAP_CREATED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(request.wrapId())
                .metadataJson(Map.of(
                        "creatorId", creatorId,
                        "nomineePartyId", request.nomineePartyId(),
                        "keyFingerprint", request.keyFingerprint()))
                .build());

        log.info("Family vault wrap created: wrapId={} creatorId={} nomineeId={}",
                request.wrapId(), creatorId, request.nomineePartyId());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new CreateWrapResponse(request.wrapId(), createdAt), requestId));
    }

    /** GET /locker/family-vault/myWraps — nominee fetches their active wraps. */
    @GetMapping("/myWraps")
    public ResponseEntity<ApiResponse<MyWrapsResponse>> myWraps(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateNomineeJwt(authHeader);
        String nomineeId = jwt.sub();

        List<MyWrapDto> wraps = dbClient.query(SELECT_MY_WRAPS, MY_WRAP_MAPPER, nomineeId);

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_MYWRAPS_FETCHED, AuditResult.SUCCESS)
                .actorId(nomineeId).actorType(PartyType.NOMINEE)
                .metadataJson(Map.of("wrapCount", wraps.size()))
                .build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(new MyWrapsResponse(wraps), requestId));
    }

    /** DELETE /locker/family-vault/wraps/{wrapId} — creator revokes a wrap. */
    @DeleteMapping("/wraps/{wrapId}")
    public ResponseEntity<ApiResponse<RevokeWrapResponse>> revokeWrap(
            @PathVariable String wrapId,
            @RequestParam(value = "reason", required = false) String reason,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        closureWriteGate.assertWritesAllowed(creatorId);

        WrapOwner owner = dbClient.queryOne(SELECT_WRAP_OWNER, WRAP_OWNER_MAPPER, wrapId)
                .orElseThrow(() -> new AppException(ErrorCode.FAMILY_VAULT_WRAP_NOT_FOUND,
                        "Wrap not found: " + wrapId));

        if (!creatorId.equals(owner.creatorId)) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Wrap is owned by a different creator");
        }
        if (!"active".equals(owner.status)) {
            throw new AppException(ErrorCode.FAMILY_VAULT_WRAP_ALREADY_REVOKED,
                    "Wrap is already in state: " + owner.status);
        }

        int updated = dbClient.execute(REVOKE_WRAP, reason, wrapId);
        if (updated != 1) {
            // Lost a race — someone else revoked between our check and update.
            throw new AppException(ErrorCode.FAMILY_VAULT_WRAP_ALREADY_REVOKED,
                    "Wrap was revoked concurrently");
        }

        Instant revokedAt = Instant.now();
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_WRAP_REVOKED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(wrapId)
                .metadataJson(Map.of(
                        "creatorId", creatorId,
                        "wrapId", wrapId,
                        "revokedReason", reason != null ? reason : ""))
                .build());

        log.info("Family vault wrap revoked: wrapId={} creatorId={} reason={}",
                wrapId, creatorId, reason);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(new RevokeWrapResponse(wrapId, revokedAt), requestId));
    }

    private JwtPayload validateCreatorJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        return jwt;
    }

    private JwtPayload validateNomineeJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.NOMINEE) {
            throw AppException.forbidden();
        }
        return jwt;
    }

    private record WrapOwner(String creatorId, String status) {}

    private record CreateWrapResponse(String wrapId, Instant createdAt) {}

    private record RevokeWrapResponse(String wrapId, Instant revokedAt) {}

    private record MyWrapsResponse(List<MyWrapDto> wraps) {}

    private record MyWrapDto(
            String wrapId,
            String creatorId,
            String creatorDisplayName,
            String specVersion,
            String saltHex,
            String keyFingerprint,
            String ephPubkeyB64,
            String nonceB64,
            String ciphertextB64,
            String authTagB64,
            Instant createdAt
    ) {}
}
