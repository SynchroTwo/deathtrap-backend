package in.deathtrap.locker.routes.status;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** GET /locker/status — per-category status + overall completeness for the
 *  authenticated creator. Used by the A2 dashboard for its periodic poll. */
@RestController
@RequestMapping("/locker")
public class LockerStatusHandler {

    private static final String SELECT_LOCKER_META =
            "SELECT locker_id, completeness_pct FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_CATEGORY_STATUS =
            "SELECT ai.category_code, ai.status, " +
            "COALESCE(bv.version, 0) AS version, " +
            "COALESCE(bv.size_bytes, 0) AS size_bytes, " +
            "bv.created_at AS uploaded_at " +
            "FROM asset_index ai " +
            "LEFT JOIN blob_versions bv ON bv.asset_id = ai.asset_id AND bv.is_current = TRUE " +
            "WHERE ai.locker_id = ? " +
            "ORDER BY ai.category_code";

    private static final RowMapper<LockerMetaRow> LOCKER_MAPPER = (rs, row) ->
            new LockerMetaRow(rs.getString("locker_id"), rs.getInt("completeness_pct"));
    private static final RowMapper<CategoryStatus> CATEGORY_MAPPER = (rs, row) -> new CategoryStatus(
            rs.getString("category_code"),
            rs.getString("status"),
            rs.getInt("version"),
            rs.getLong("size_bytes"),
            rs.getTimestamp("uploaded_at") != null ? rs.getTimestamp("uploaded_at").toInstant() : null);

    private final DbClient dbClient;
    private final JwtService jwtService;

    public LockerStatusHandler(DbClient dbClient, JwtService jwtService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
    }

    @GetMapping("/status")
    public ResponseEntity<ApiResponse<LockerStatusResponse>> status(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.CREATOR) {
            throw AppException.forbidden();
        }
        String creatorId = jwt.sub();

        LockerMetaRow meta = dbClient.queryOne(SELECT_LOCKER_META, LOCKER_MAPPER, creatorId)
                .orElseThrow(() -> AppException.notFound("locker"));

        List<CategoryStatus> categories = new ArrayList<>(
                dbClient.query(SELECT_CATEGORY_STATUS, CATEGORY_MAPPER, meta.lockerId()));

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new LockerStatusResponse(categories, meta.completenessPct()), requestId));
    }

    record LockerMetaRow(String lockerId, int completenessPct) {}

    record CategoryStatus(
            String code,
            String status,
            int version,
            long sizeBytes,
            Instant lastUpdatedAt
    ) {}

    record LockerStatusResponse(
            List<CategoryStatus> categories,
            int completenessPct
    ) {}
}
