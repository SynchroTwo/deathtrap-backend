package in.deathtrap.locker.routes.lawyer;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.locker.config.JwtService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** D007 fix — GET /lawyer for the creator dashboard. Returns the lawyer assigned
 *  to the caller's locker (via {@code locker_meta.assigned_lawyer_id}), or
 *  {@code {"lawyer": null}} when no lawyer is assigned. Maps the same path
 *  under {@code /lawyer} (root) and {@code /locker/lawyer} so the FE can call
 *  either without a client change. */
@RestController
@RequestMapping({"/lawyer", "/locker/lawyer"})
public class LawyerLookupHandler {

    private static final Logger log = LoggerFactory.getLogger(LawyerLookupHandler.class);

    private static final String SELECT_LAWYER_FOR_CREATOR =
            "SELECT l.lawyer_id, l.full_name, l.mobile, l.email, l.bar_council, l.enrollment_no, " +
            "l.bar_verified, l.bar_verified_at, l.status::text AS status, l.created_at " +
            "FROM locker_meta lm " +
            "JOIN lawyers l ON l.lawyer_id = lm.assigned_lawyer_id " +
            "WHERE lm.user_id = ? LIMIT 1";

    private static final RowMapper<LawyerRow> LAWYER_MAPPER = (rs, row) -> new LawyerRow(
            rs.getString("lawyer_id"),
            rs.getString("full_name"),
            rs.getString("mobile"),
            rs.getString("email"),
            rs.getString("bar_council"),
            rs.getString("enrollment_no"),
            rs.getBoolean("bar_verified"),
            Optional.ofNullable(rs.getTimestamp("bar_verified_at"))
                    .map(Timestamp::toInstant).orElse(null),
            rs.getString("status"),
            rs.getTimestamp("created_at").toInstant());

    private final DbClient dbClient;
    private final JwtService jwtService;

    public LawyerLookupHandler(DbClient dbClient, JwtService jwtService) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
    }

    /** GET /lawyer — returns {@code {"lawyer": ...|null}}. Creator JWT required;
     *  partyType must be CREATOR (a nominee/lawyer should not see another locker's
     *  assigned lawyer through this surface). */
    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAssignedLawyer(
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateCreatorJwt(authHeader);
        String creatorId = jwt.sub();

        Optional<LawyerRow> rowOpt = dbClient.queryOne(SELECT_LAWYER_FOR_CREATOR, LAWYER_MAPPER, creatorId);
        Map<String, Object> response = new LinkedHashMap<>();
        if (rowOpt.isEmpty()) {
            response.put("lawyer", null);
        } else {
            LawyerRow row = rowOpt.get();
            Map<String, Object> lawyer = new LinkedHashMap<>();
            lawyer.put("lawyerId", row.lawyerId);
            lawyer.put("fullName", row.fullName);
            lawyer.put("mobile", row.mobile);
            lawyer.put("email", row.email);
            lawyer.put("barCouncil", row.barCouncil);
            lawyer.put("enrollmentNo", row.enrollmentNo);
            lawyer.put("barVerified", row.barVerified);
            lawyer.put("barVerifiedAt", row.barVerifiedAt != null ? row.barVerifiedAt.toString() : null);
            lawyer.put("status", row.status);
            lawyer.put("createdAt", row.createdAt.toString());
            response.put("lawyer", lawyer);
        }

        log.info("Lawyer lookup: creatorId={} hasLawyer={}", creatorId, rowOpt.isPresent());
        return ResponseEntity.ok(ApiResponse.ok(response, UUID.randomUUID().toString()));
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

    private record LawyerRow(String lawyerId, String fullName, String mobile, String email,
            String barCouncil, String enrollmentNo, boolean barVerified, Instant barVerifiedAt,
            String status, Instant createdAt) {}
}
