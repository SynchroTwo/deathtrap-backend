package in.deathtrap.locker.routes.backup;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E003 Phase 1 — managed backup opt-in toggle on the creator's locker. */
@RestController
@RequestMapping("/locker/managed-backup")
public class ManagedBackupHandler {

    private static final String SPEC_VERSION = "v1";

    private static final String SELECT_LOCKER_BACKUP =
            "SELECT locker_id, managed_backup_enabled, managed_backup_enabled_at " +
            "FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String UPDATE_ENABLE =
            "UPDATE locker_meta SET managed_backup_enabled = TRUE, " +
            "managed_backup_enabled_at = ?, updated_at = NOW() WHERE locker_id = ?";
    private static final String UPDATE_DISABLE =
            "UPDATE locker_meta SET managed_backup_enabled = FALSE, " +
            "managed_backup_enabled_at = NULL, updated_at = NOW() WHERE locker_id = ?";

    private static final RowMapper<LockerBackupRow> ROW_MAPPER = (rs, row) -> new LockerBackupRow(
            rs.getString("locker_id"),
            rs.getBoolean("managed_backup_enabled"),
            Optional.ofNullable(rs.getTimestamp("managed_backup_enabled_at"))
                    .map(Timestamp::toInstant).orElse(null));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs ManagedBackupHandler with required dependencies. */
    public ManagedBackupHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** GET /locker/managed-backup/status — current toggle state for the caller's locker. */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<ManagedBackupStatusResponse>> getStatus(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        LockerBackupRow row = loadLocker(jwt.sub());

        return ok(row.enabled(), row.enabledAt());
    }

    /** POST /locker/managed-backup/enable — opt in. Idempotent: no-op + 200 when already enabled. */
    @PostMapping("/enable")
    public ResponseEntity<ApiResponse<ManagedBackupStatusResponse>> enable(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();
        LockerBackupRow row = loadLocker(creatorId);

        if (row.enabled()) {
            return ok(true, row.enabledAt());
        }

        Instant now = Instant.now();
        dbClient.execute(UPDATE_ENABLE, now, row.lockerId());

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.BACKUP_MANAGED_ENABLED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(row.lockerId()).build());

        return ok(true, now);
    }

    /** POST /locker/managed-backup/disable — opt out. Idempotent: no-op + 200 when already disabled. */
    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<ManagedBackupStatusResponse>> disable(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();
        LockerBackupRow row = loadLocker(creatorId);

        if (!row.enabled()) {
            return ok(false, null);
        }

        dbClient.execute(UPDATE_DISABLE, row.lockerId());

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.BACKUP_MANAGED_DISABLED, AuditResult.SUCCESS)
                .actorId(creatorId).actorType(PartyType.CREATOR).targetId(row.lockerId()).build());

        return ok(false, null);
    }

    private LockerBackupRow loadLocker(String creatorId) {
        List<LockerBackupRow> rows = dbClient.query(SELECT_LOCKER_BACKUP, ROW_MAPPER, creatorId);
        if (rows.isEmpty()) {
            throw AppException.notFound("locker");
        }
        return rows.get(0);
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

    private static ResponseEntity<ApiResponse<ManagedBackupStatusResponse>> ok(
            boolean enabled, Instant enabledAt) {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new ManagedBackupStatusResponse(enabled, enabledAt, SPEC_VERSION), requestId));
    }

    private record LockerBackupRow(String lockerId, boolean enabled, Instant enabledAt) {}

    private record ManagedBackupStatusResponse(boolean enabled, Instant enabledAt, String specVersion) {}
}
