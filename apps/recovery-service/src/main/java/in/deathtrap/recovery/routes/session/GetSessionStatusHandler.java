package in.deathtrap.recovery.routes.session;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryBlobLayerRowMapper.RecoveryBlobLayer;
import in.deathtrap.recovery.rowmapper.RecoveryPeelEventRowMapper;
import in.deathtrap.recovery.rowmapper.RecoveryPeelEventRowMapper.RecoveryPeelEvent;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper;
import in.deathtrap.recovery.rowmapper.RecoverySessionRowMapper.RecoverySession;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Handles polling the status of a recovery session. */
@RestController
@RequestMapping("/recovery/session")
public class GetSessionStatusHandler {

    private static final String SELECT_SESSION =
            "SELECT session_id, creator_id, trigger_id, blob_id, status, initiated_at, " +
            "locked_until, completed_at, created_at FROM recovery_sessions WHERE session_id = ? LIMIT 1";
    private static final String SELECT_AUTH_LAYER =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND party_id = ? LIMIT 1";
    private static final String UPDATE_SESSION_IN_PROGRESS =
            "UPDATE recovery_sessions SET status = 'in_progress', updated_at = NOW() WHERE session_id = ?";
    private static final String SELECT_PEEL_EVENTS =
            "SELECT peel_id, session_id, layer_id, party_id, party_type, layer_order, " +
            "intermediate_hash, peeled_at, created_at " +
            "FROM recovery_peel_events WHERE session_id = ? ORDER BY peeled_at ASC";
    private static final String SELECT_LAYER_COUNT =
            "SELECT layer_count FROM recovery_blobs WHERE blob_id = ? LIMIT 1";
    private static final String SELECT_NEXT_PARTY =
            "SELECT layer_id, blob_id, layer_order, party_id, party_type, pubkey_id, " +
            "key_fingerprint, created_at " +
            "FROM recovery_blob_layers WHERE blob_id = ? AND layer_order = ? LIMIT 1";

    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);

    private final DbClient dbClient;
    private final JwtService jwtService;

    /** Constructs GetSessionStatusHandler with required dependencies. */
    public GetSessionStatusHandler(DbClient dbClient, JwtService jwtService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
    }

    /** GET /recovery/session/{sessionId} — returns current session status and peel progress. */
    @GetMapping("/{sessionId}")
    public ResponseEntity<ApiResponse<SessionStatusResponse>> getStatus(
            @PathVariable String sessionId,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        String partyId = jwt.sub();

        List<RecoverySession> sessionRows = dbClient.query(SELECT_SESSION,
                RecoverySessionRowMapper.INSTANCE, sessionId);
        if (sessionRows.isEmpty()) {
            throw AppException.notFound("recovery_session");
        }
        RecoverySession session = sessionRows.get(0);

        if (!partyId.equals(session.creatorId())) {
            List<RecoveryBlobLayer> authRows = dbClient.query(SELECT_AUTH_LAYER,
                    RecoveryBlobLayerRowMapper.INSTANCE, session.blobId(), partyId);
            if (authRows.isEmpty()) {
                throw new AppException(ErrorCode.AUTH_FORBIDDEN, "Not authorized for this session");
            }
        }

        if ("initiated".equals(session.status()) && Instant.now().isAfter(session.lockedUntil())) {
            dbClient.execute(UPDATE_SESSION_IN_PROGRESS, sessionId);
            List<RecoverySession> reloaded = dbClient.query(SELECT_SESSION,
                    RecoverySessionRowMapper.INSTANCE, sessionId);
            if (!reloaded.isEmpty()) {
                session = reloaded.get(0);
            }
        }

        List<RecoveryPeelEvent> peelEvents = dbClient.query(SELECT_PEEL_EVENTS,
                RecoveryPeelEventRowMapper.INSTANCE, sessionId);

        List<Integer> layerCountRows = dbClient.query(SELECT_LAYER_COUNT, INT_MAPPER, session.blobId());
        int totalLayers = layerCountRows.isEmpty() ? 0 : layerCountRows.get(0);

        int layersPeeled = peelEvents.size();
        boolean timelockActive = Instant.now().isBefore(session.lockedUntil());

        Integer nextLayerOrder = null;
        String nextPartyId = null;
        String nextPartyType = null;
        if (layersPeeled < totalLayers) {
            int expectedNext = layersPeeled + 1;
            List<RecoveryBlobLayer> nextPartyRows = dbClient.query(SELECT_NEXT_PARTY,
                    RecoveryBlobLayerRowMapper.INSTANCE, session.blobId(), expectedNext);
            if (!nextPartyRows.isEmpty()) {
                nextLayerOrder = expectedNext;
                nextPartyId = nextPartyRows.get(0).partyId();
                nextPartyType = nextPartyRows.get(0).partyType();
            }
        }

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(new SessionStatusResponse(
                session.sessionId(), session.status(), session.creatorId(),
                session.lockedUntil(), timelockActive, totalLayers, layersPeeled,
                nextLayerOrder, nextPartyId, nextPartyType, session.completedAt()), requestId));
    }

    private record SessionStatusResponse(
            String sessionId,
            String status,
            String creatorId,
            Instant lockedUntil,
            boolean timelockActive,
            int totalLayers,
            int layersPeeled,
            Integer nextLayerOrder,
            String nextPartyId,
            String nextPartyType,
            Instant completedAt
    ) {}
}
