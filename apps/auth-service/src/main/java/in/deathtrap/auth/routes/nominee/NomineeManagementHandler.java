package in.deathtrap.auth.routes.nominee;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.CreateNomineeRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.NomineeView;
import in.deathtrap.common.types.dto.PubkeyView;
import in.deathtrap.common.types.dto.UpdateNomineeRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Creator-authenticated nominee CRUD for Sprint A3 (path A).
 *
 * <p>All routes live under the already-routed {@code /auth} prefix (no CDK change).
 * The signed invite token itself is generated client-side after {@code POST /auth/nominees}
 * returns the server-assigned {@code nomineeId}; the backend verifies that token only on
 * {@code POST /auth/nominee/accept} (see NomineeAcceptHandler).
 */
@RestController
@RequestMapping("/auth/nominees")
public class NomineeManagementHandler {

    private static final String VIEW_COLUMNS =
            "n.nominee_id, n.creator_id, n.full_name, n.email, n.mobile, n.status::text AS status, " +
            "n.created_at, n.registered_at, n.removed_at, pk.public_key_pem, pk.key_fingerprint ";
    private static final String VIEW_FROM =
            "FROM nominees n LEFT JOIN party_public_keys pk " +
            "ON pk.party_id = n.nominee_id AND pk.party_type = 'nominee'::party_type_enum AND pk.is_active = true ";

    private static final String SELECT_LIST =
            "SELECT " + VIEW_COLUMNS + VIEW_FROM +
            "WHERE n.creator_id = ? ORDER BY n.created_at ASC";
    private static final String SELECT_ONE =
            "SELECT " + VIEW_COLUMNS + VIEW_FROM +
            "WHERE n.nominee_id = ? AND n.creator_id = ? LIMIT 1";
    private static final String INSERT_NOMINEE =
            "INSERT INTO nominees (nominee_id, creator_id, full_name, email, mobile, status, " +
            "invite_expires_at, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, ?, 'invited'::nominee_status_enum, ?, ?, ?)";
    private static final String UPDATE_FIELDS =
            "UPDATE nominees SET full_name = COALESCE(?, full_name), email = COALESCE(?, email), " +
            "mobile = COALESCE(?, mobile) " +
            "WHERE nominee_id = ? AND creator_id = ? AND status <> 'removed'::nominee_status_enum";
    private static final String SOFT_DELETE =
            "UPDATE nominees SET status = 'removed'::nominee_status_enum, removed_at = ? " +
            "WHERE nominee_id = ? AND creator_id = ? AND status <> 'removed'::nominee_status_enum";
    private static final String UPDATE_RESEND =
            "UPDATE nominees SET last_resend_at = ? " +
            "WHERE nominee_id = ? AND creator_id = ? AND status = 'invited'::nominee_status_enum";
    private static final String SELECT_PUBKEY =
            "SELECT pk.public_key_pem, pk.key_fingerprint FROM party_public_keys pk " +
            "JOIN nominees n ON n.nominee_id = pk.party_id " +
            "WHERE pk.party_id = ? AND pk.party_type = 'nominee'::party_type_enum AND pk.is_active = true " +
            "AND n.creator_id = ? LIMIT 1";

    private static final RowMapper<NomineeView> VIEW_MAPPER = (rs, row) -> new NomineeView(
            rs.getString("nominee_id"),
            rs.getString("creator_id"),
            rs.getString("full_name"),
            rs.getString("email"),
            rs.getString("mobile"),
            rs.getString("status"),
            rs.getString("public_key_pem"),
            rs.getString("key_fingerprint"),
            tsToIso(rs.getTimestamp("created_at")),
            tsToIso(rs.getTimestamp("registered_at")),
            tsToIso(rs.getTimestamp("removed_at")));
    private static final RowMapper<PubkeyView> PUBKEY_MAPPER = (rs, row) ->
            new PubkeyView(rs.getString("public_key_pem"), rs.getString("key_fingerprint"));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs NomineeManagementHandler with required dependencies. */
    public NomineeManagementHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/nominees — creates a nominee in status='invited'; returns the new record with its id. */
    @PostMapping
    public ResponseEntity<ApiResponse<NomineeView>> create(
            @RequestBody @Valid CreateNomineeRequest request,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = creatorIdFrom(authHeader);
        Instant now = Instant.now();
        Instant expiresAt = parseOptionalInstant(request.expiresAt());
        String nomineeId = CsprngUtil.randomUlid();

        dbClient.execute(INSERT_NOMINEE, nomineeId, creatorId, request.fullName(),
                request.email(), request.mobile(),
                expiresAt != null ? Timestamp.from(expiresAt) : null,
                Timestamp.from(now), Timestamp.from(now));

        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_INVITED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(nomineeId).build());

        NomineeView view = new NomineeView(nomineeId, creatorId, request.fullName(),
                request.email(), request.mobile(), "invited", null, null,
                now.toString(), null, null);
        return ResponseEntity.status(201).body(ApiResponse.ok(view, UUID.randomUUID().toString()));
    }

    /** GET /auth/nominees — lists this creator's nominees (including removed). */
    @GetMapping
    public ResponseEntity<ApiResponse<List<NomineeView>>> list(
            @RequestHeader("Authorization") String authHeader) {
        String creatorId = creatorIdFrom(authHeader);
        List<NomineeView> nominees = dbClient.query(SELECT_LIST, VIEW_MAPPER, creatorId);
        return ResponseEntity.ok(ApiResponse.ok(nominees, UUID.randomUUID().toString()));
    }

    /** PATCH /auth/nominees/{id} — updates only the supplied (non-null) fields. */
    @PatchMapping("/{id}")
    public ResponseEntity<ApiResponse<NomineeView>> update(
            @PathVariable("id") String nomineeId,
            @RequestBody @Valid UpdateNomineeRequest request,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = creatorIdFrom(authHeader);
        int updated = dbClient.execute(UPDATE_FIELDS, request.fullName(), request.email(),
                request.mobile(), nomineeId, creatorId);
        if (updated == 0) {
            throw AppException.nomineeNotFound();
        }
        return ResponseEntity.ok(ApiResponse.ok(requireView(nomineeId, creatorId),
                UUID.randomUUID().toString()));
    }

    /** DELETE /auth/nominees/{id} — soft-deletes (status='removed'). */
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> remove(
            @PathVariable("id") String nomineeId,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = creatorIdFrom(authHeader);
        int removed = dbClient.execute(SOFT_DELETE, Timestamp.from(Instant.now()), nomineeId, creatorId);
        if (removed == 0) {
            throw AppException.nomineeNotFound();
        }
        auditWriter.write(AuditWritePayload.builder(AuditEventType.NOMINEE_REMOVED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(nomineeId).build());
        return ResponseEntity.status(204).build();
    }

    /** POST /auth/nominees/{id}/resend — records a resend; the token is regenerated client-side. */
    @PostMapping("/{id}/resend")
    public ResponseEntity<ApiResponse<ResendResponse>> resend(
            @PathVariable("id") String nomineeId,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = creatorIdFrom(authHeader);
        Instant now = Instant.now();
        int touched = dbClient.execute(UPDATE_RESEND, Timestamp.from(now), nomineeId, creatorId);
        if (touched == 0) {
            throw AppException.nomineeNotFound();
        }
        return ResponseEntity.ok(ApiResponse.ok(
                new ResendResponse(nomineeId, now.toString()), UUID.randomUUID().toString()));
    }

    /** GET /auth/nominees/{id}/pubkey — the nominee's active pubkey (404 until they accept). */
    @GetMapping("/{id}/pubkey")
    public ResponseEntity<ApiResponse<PubkeyView>> pubkey(
            @PathVariable("id") String nomineeId,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = creatorIdFrom(authHeader);
        PubkeyView view = dbClient.queryOne(SELECT_PUBKEY, PUBKEY_MAPPER, nomineeId, creatorId)
                .orElseThrow(AppException::nomineeNotFound);
        return ResponseEntity.ok(ApiResponse.ok(view, UUID.randomUUID().toString()));
    }

    private NomineeView requireView(String nomineeId, String creatorId) {
        Optional<NomineeView> view = dbClient.queryOne(SELECT_ONE, VIEW_MAPPER, nomineeId, creatorId);
        return view.orElseThrow(AppException::nomineeNotFound);
    }

    private String creatorIdFrom(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        return jwt.sub();
    }

    private static Instant parseOptionalInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException ex) {
            throw AppException.validationFailed(Map.of("expiresAt", "Must be an ISO-8601 instant"));
        }
    }

    private static String tsToIso(Timestamp ts) {
        return ts == null ? null : ts.toInstant().toString();
    }

    private record ResendResponse(String nomineeId, String lastResendAt) {}
}
