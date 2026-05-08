package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.PeelRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles layer peel submissions during an active recovery session. */
@RestController
@RequestMapping("/recovery/session")
public class PeelHandler {

    private static final Logger log = LoggerFactory.getLogger(PeelHandler.class);

    private static final String SELECT_SESSION =
            "SELECT session_id, creator_id, trigger_id, blob_id, status, initiated_at, " +
            "locked_until, completed_at, created_at FROM recovery_sessions WHERE session_id = ? LIMIT 1";
    private static final String SELECT_MY_LAYER =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND party_id = ? AND party_type = ?::party_type_enum LIMIT 1";
    private static final String SELECT_MAX_PEELED =
            "SELECT COALESCE(MAX(layer_order), 0) FROM recovery_peel_events WHERE session_id = ?";
    private static final String SELECT_ALREADY_PEELED =
            "SELECT peel_id FROM recovery_peel_events " +
            "WHERE session_id = ? AND party_id = ? AND party_type = ?::party_type_enum LIMIT 1";
    private static final String INSERT_PEEL_EVENT =
            "INSERT INTO recovery_peel_events (peel_id, session_id, layer_id, party_id, " +
            "party_type, layer_order, intermediate_hash, peeled_at, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())";
    private static final String UPDATE_SESSION_IN_PROGRESS =
            "UPDATE recovery_sessions SET status = 'in_progress', updated_at = NOW() WHERE session_id = ?";
    private static final String SELECT_LAYER_COUNT =
            "SELECT layer_count FROM recovery_blobs WHERE blob_id = ? LIMIT 1";
    private static final String SELECT_PEEL_COUNT =
            "SELECT COUNT(*) FROM recovery_peel_events WHERE session_id = ?";
    private static final String UPDATE_SESSION_COMPLETED =
            "UPDATE recovery_sessions SET status = 'completed', completed_at = NOW(), " +
            "updated_at = NOW() WHERE session_id = ?";
    private static final String SELECT_NEXT_PARTY =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND layer_order = ? LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs PeelHandler with required dependencies. */
    public PeelHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /recovery/session/{sessionId}/peel — submits a decrypted layer, advances session. */
    @PostMapping("/{sessionId}/peel")
    public ResponseEntity<ApiResponse<PeelResponse>> peel(
            @PathVariable String sessionId,
            @RequestBody @Valid PeelRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();
        PartyType partyType = jwt.partyType();

        if (partyType == PartyType.CREATOR || partyType == PartyType.ADMIN
                || partyType == PartyType.SYSTEM) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Only nominees and lawyers can peel layers");
        }

        List<RecoverySession> sessionRows = dbClient.query(SELECT_SESSION,
                RecoverySessionRowMapper.INSTANCE, sessionId);
        if (sessionRows.isEmpty()) {
            throw AppException.notFound("recovery_session");
        }
        RecoverySession session = sessionRows.get(0);

        if (Instant.now().isBefore(session.lockedUntil())) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "Recovery session is still in the 48-hour safety window. Cannot peel yet. " +
                    "Retry after: " + session.lockedUntil());
        }

        if (!"initiated".equals(session.status()) && !"in_progress".equals(session.status())) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "Recovery session is not active (status: " + session.status() + ")");
        }

        String partyTypeStr = partyType.name().toLowerCase();
        List<RecoveryBlobLayer> layerRows = dbClient.query(SELECT_MY_LAYER,
                RecoveryBlobLayerRowMapper.INSTANCE, session.blobId(), partyId, partyTypeStr);
        if (layerRows.isEmpty()) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Not a party in this recovery blob");
        }
        RecoveryBlobLayer myLayer = layerRows.get(0);

        List<Integer> maxPeeledRows = dbClient.query(SELECT_MAX_PEELED, INT_MAPPER, sessionId);
        int maxPeeled = maxPeeledRows.isEmpty() ? 0 : maxPeeledRows.get(0);
        int expectedLayerOrder = maxPeeled + 1;

        if (myLayer.layerOrder() != expectedLayerOrder) {
            throw new AppException(ErrorCode.VALIDATION_FAILED,
                    "Not your turn to peel. Expected layer " + expectedLayerOrder +
                    ", your layer is " + myLayer.layerOrder() + ".");
        }

        List<String> alreadyPeeledRows = dbClient.query(SELECT_ALREADY_PEELED,
                STRING_MAPPER, sessionId, partyId, partyTypeStr);
        if (!alreadyPeeledRows.isEmpty()) {
            throw new AppException(ErrorCode.CONFLICT, "You have already peeled your layer.");
        }

        byte[] intermediateBytes = Base64.getDecoder().decode(request.intermediateCiphertextB64());
        String intermediateHash = Sha256Util.hashHex(intermediateBytes);

        String peelId = CsprngUtil.randomUlid();
        String finalStatus = dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_PEEL_EVENT, peelId, sessionId, myLayer.layerId(),
                    partyId, partyTypeStr, myLayer.layerOrder(), intermediateHash);
            dbClient.execute(UPDATE_SESSION_IN_PROGRESS, sessionId);

            List<Integer> layerCountRows = dbClient.query(SELECT_LAYER_COUNT,
                    INT_MAPPER, session.blobId());
            int layerCount = layerCountRows.isEmpty() ? 0 : layerCountRows.get(0);
            List<Integer> peelCountRows = dbClient.query(SELECT_PEEL_COUNT, INT_MAPPER, sessionId);
            int peelCount = peelCountRows.isEmpty() ? 0 : peelCountRows.get(0);

            if (peelCount >= layerCount) {
                dbClient.execute(UPDATE_SESSION_COMPLETED, sessionId);
                auditWriter.write(AuditWritePayload
                        .builder(AuditEventType.RECOVERY_SESSION_COMPLETED, AuditResult.SUCCESS)
                        .actorId(partyId).actorType(partyType).targetId(sessionId)
                        .build());
                return "completed";
            }
            return "in_progress";
        });

        int layersRemaining = 0;
        String nextPartyId = null;
        String nextPartyType = null;
        Instant completedAt = null;
        if ("completed".equals(finalStatus)) {
            completedAt = Instant.now();
        } else {
            int nextLayerOrder = myLayer.layerOrder() + 1;
            List<RecoveryBlobLayer> nextPartyRows = dbClient.query(SELECT_NEXT_PARTY,
                    RecoveryBlobLayerRowMapper.INSTANCE, session.blobId(), nextLayerOrder);
            if (!nextPartyRows.isEmpty()) {
                nextPartyId = nextPartyRows.get(0).partyId();
                nextPartyType = nextPartyRows.get(0).partyType();
                layersRemaining = 1;
            }
        }

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.RECOVERY_LAYER_PEELED, AuditResult.SUCCESS)
                .actorId(partyId).actorType(partyType).targetId(sessionId)
                .metadataJson(Map.of("layerOrder", myLayer.layerOrder(),
                        "layersRemaining", layersRemaining))
                .build());

        log.info("Layer peeled: sessionId={} partyId={} layerOrder={} status={}",
                sessionId, partyId, myLayer.layerOrder(), finalStatus);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(new PeelResponse(
                peelId, myLayer.layerOrder(), finalStatus, layersRemaining,
                nextPartyId, nextPartyType, completedAt), requestId));
    }

    private record PeelResponse(
            String peelId,
            int layerOrder,
            String sessionStatus,
            int layersRemaining,
            String nextPartyId,
            String nextPartyType,
            Instant completedAt
    ) {}
}
