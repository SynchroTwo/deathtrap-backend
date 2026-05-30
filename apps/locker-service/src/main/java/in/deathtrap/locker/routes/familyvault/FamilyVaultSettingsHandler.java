package in.deathtrap.locker.routes.familyvault;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E011 Phase 1C §10.3 + §10.4 — Family Vault access-notification settings.
 *  PATCH toggles the creator's opt-in for the hourly batched access fan-out;
 *  GET returns the current toggle plus a per-nominee 24h access summary. */
@RestController
@RequestMapping("/locker/family-vault/notification-settings")
public class FamilyVaultSettingsHandler {

    private static final Logger log = LoggerFactory.getLogger(FamilyVaultSettingsHandler.class);

    private static final String SELECT_TOGGLE =
            "SELECT notify_on_nominee_access FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String UPDATE_TOGGLE =
            "UPDATE locker_meta SET notify_on_nominee_access = ?, updated_at = NOW() " +
            "WHERE user_id = ?";
    private static final String SELECT_RECENT_ACCESS =
            "SELECT can.nominee_party_id, u.full_name AS nominee_display_name, " +
            "can.pending_count, can.last_access_at " +
            "FROM creator_access_notification_log can " +
            "LEFT JOIN users u ON u.user_id = can.nominee_party_id " +
            "WHERE can.creator_id = ? AND can.last_access_at >= NOW() - INTERVAL '24 hours' " +
            "ORDER BY can.last_access_at DESC";

    private static final RowMapper<Boolean> BOOLEAN_MAPPER = (rs, row) -> rs.getBoolean(1);
    private static final RowMapper<RecentAccessRow> RECENT_ACCESS_MAPPER = (rs, row) -> new RecentAccessRow(
            rs.getString("nominee_party_id"),
            rs.getString("nominee_display_name"),
            rs.getInt("pending_count"),
            Optional.ofNullable(rs.getTimestamp("last_access_at"))
                    .map(Timestamp::toInstant).orElse(null));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    public FamilyVaultSettingsHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** GET /locker/family-vault/notification-settings — current toggle + recent-access summary. */
    @GetMapping
    public ResponseEntity<ApiResponse<SettingsResponse>> getSettings(
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = validateCreatorJwt(authHeader).sub();

        Boolean current = dbClient.queryOne(SELECT_TOGGLE, BOOLEAN_MAPPER, creatorId)
                .orElseThrow(() -> AppException.notFound("locker"));
        List<RecentAccessRow> rows = dbClient.query(SELECT_RECENT_ACCESS, RECENT_ACCESS_MAPPER, creatorId);
        List<RecentAccess> recent = rows.stream()
                .map(r -> new RecentAccess(r.nomineePartyId, r.nomineeDisplayName, r.pendingCount, r.lastAccessAt))
                .toList();

        return ResponseEntity.ok(ApiResponse.ok(
                new SettingsResponse(current, recent), UUID.randomUUID().toString()));
    }

    /** PATCH /locker/family-vault/notification-settings — flip the toggle. */
    @PatchMapping
    public ResponseEntity<ApiResponse<UpdateResponse>> updateSettings(
            @RequestBody @Valid UpdateRequest body,
            @RequestHeader("Authorization") String authHeader) {

        String creatorId = validateCreatorJwt(authHeader).sub();
        if (body.notifyOnNomineeAccess() == null) {
            throw new AppException(ErrorCode.FAMILY_VAULT_NOTIFY_SETTING_INVALID,
                    "notifyOnNomineeAccess is required");
        }
        Boolean previous = dbClient.queryOne(SELECT_TOGGLE, BOOLEAN_MAPPER, creatorId).orElse(null);
        if (previous == null) {
            throw AppException.notFound("locker");
        }
        int updated = dbClient.execute(UPDATE_TOGGLE, body.notifyOnNomineeAccess(), creatorId);
        if (updated != 1) {
            throw AppException.notFound("locker");
        }
        Instant now = Instant.now();
        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.FAMILY_VAULT_NOTIFY_SETTING_CHANGED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(creatorId)
                .metadataJson(Map.of(
                        "previous", previous,
                        "next", body.notifyOnNomineeAccess()))
                .build());
        log.info("FV notify setting changed: creatorId={} previous={} next={}",
                creatorId, previous, body.notifyOnNomineeAccess());

        return ResponseEntity.ok(ApiResponse.ok(
                new UpdateResponse(body.notifyOnNomineeAccess(), now), UUID.randomUUID().toString()));
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

    public record UpdateRequest(@NotNull Boolean notifyOnNomineeAccess) {}

    public record UpdateResponse(boolean notifyOnNomineeAccess, Instant updatedAt) {}

    public record SettingsResponse(boolean notifyOnNomineeAccess, List<RecentAccess> recentAccess) {}

    public record RecentAccess(String nomineePartyId, String nomineeDisplayName,
            int last24hAccessCount, Instant lastAccessAt) {}

    private record RecentAccessRow(String nomineePartyId, String nomineeDisplayName,
            int pendingCount, Instant lastAccessAt) {}
}
