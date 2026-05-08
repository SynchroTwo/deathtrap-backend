package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.InitiateSessionRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobRowMapper.RecoveryBlob;
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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles initiating a recovery session after death trigger is confirmed. */
@RestController
@RequestMapping("/recovery/session")
public class InitiateSessionHandler {

    private static final Logger log = LoggerFactory.getLogger(InitiateSessionHandler.class);

    private static final String SELECT_TRIGGER =
            "SELECT trigger_id FROM trigger_events " +
            "WHERE creator_id = ? AND status IN ('approved', 'active') " +
            "ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_ACTIVE_SESSION =
            "SELECT session_id FROM recovery_sessions " +
            "WHERE creator_id = ? AND status IN ('initiated', 'in_progress') LIMIT 1";
    private static final String SELECT_ACTIVE_BLOB =
            "SELECT blob_id, creator_id, s3_key, layer_count, status, built_at, created_at " +
            "FROM recovery_blobs WHERE creator_id = ? AND status = 'active' LIMIT 1";
    private static final String INSERT_SESSION =
            "INSERT INTO recovery_sessions (session_id, creator_id, trigger_id, blob_id, status, " +
            "initiated_at, locked_until, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, 'initiated', ?, ?, NOW(), NOW())";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs InitiateSessionHandler with required dependencies. */
    public InitiateSessionHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /recovery/session — initiates a recovery session with 48-hour timelock. */
    @PostMapping
    public ResponseEntity<ApiResponse<InitiateSessionResponse>> initiateSession(
            @RequestBody @Valid InitiateSessionRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        if (partyType == PartyType.CREATOR) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                    "Creator cannot initiate recovery session");
        }

        String creatorId = request.creatorId();

        List<String> triggerRows = dbClient.query(SELECT_TRIGGER, STRING_MAPPER, creatorId);
        if (triggerRows.isEmpty()) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "No approved trigger event found for this creator");
        }
        String triggerId = triggerRows.get(0);

        List<String> sessionRows = dbClient.query(SELECT_ACTIVE_SESSION, STRING_MAPPER, creatorId);
        if (!sessionRows.isEmpty()) {
            throw new AppException(ErrorCode.CONFLICT,
                    "A recovery session is already in progress for this creator");
        }

        List<RecoveryBlob> blobRows = dbClient.query(SELECT_ACTIVE_BLOB,
                RecoveryBlobRowMapper.INSTANCE, creatorId);
        if (blobRows.isEmpty()) {
            throw AppException.notFound("recovery_blob");
        }
        RecoveryBlob blob = blobRows.get(0);

        String sessionId = CsprngUtil.randomUlid();
        Instant initiatedAt = Instant.now();
        Instant lockedUntil = initiatedAt.plus(48, ChronoUnit.HOURS);

        dbClient.execute(INSERT_SESSION, sessionId, creatorId, triggerId, blob.blobId(),
                java.sql.Timestamp.from(initiatedAt),
                java.sql.Timestamp.from(lockedUntil));

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.RECOVERY_SESSION_INITIATED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).targetId(sessionId)
                .metadataJson(Map.of("creatorId", creatorId, "lockedUntil", lockedUntil.toString()))
                .build());

        log.info("Recovery session initiated: sessionId={} creatorId={} partyId={}",
                sessionId, creatorId, partyId);

        String requestId = UUID.randomUUID().toString();
        String message = "Recovery session initiated. 48-hour safety window active. " +
                "Creator can halt until " + lockedUntil + ".";
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new InitiateSessionResponse(sessionId, "initiated", lockedUntil, message),
                requestId));
    }

    private record InitiateSessionResponse(
            String sessionId, String status, Instant lockedUntil, String message) {}
}
