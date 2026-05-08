package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.domain.Lawyer;
import in.deathtrap.common.types.dto.ApproveLawyerRequest;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.LawyerStatus;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.Valid;
import java.time.Instant;
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

/** Handles admin approval of a pending lawyer. */
@RestController
@RequestMapping("/auth/lawyer")
public class ApproveLawyerHandler {

    private static final Logger log = LoggerFactory.getLogger(ApproveLawyerHandler.class);

    private static final String SELECT_LAWYER =
            "SELECT lawyer_id, full_name, mobile, email, bar_council, enrollment_no, " +
            "bar_verified, bar_verified_at, status, kyc_admin_approved, kyc_approved_at, " +
            "created_at, updated_at FROM lawyers WHERE lawyer_id = ? LIMIT 1";
    private static final String UPDATE_LAWYER_ACTIVE =
            "UPDATE lawyers SET status = 'active'::lawyer_status_enum, kyc_admin_approved = true, " +
            "kyc_approved_at = ?, updated_at = ? WHERE lawyer_id = ?";
    private static final String UPDATE_KYC_FLAG_VERIFIED =
            "UPDATE kyc_flags SET passed = true, checked_at = ? " +
            "WHERE party_id = ? AND party_type = 'lawyer'::party_type_enum " +
            "AND kyc_type = 'bar_council'::kyc_type_enum AND passed = false";

    private static final RowMapper<Lawyer> LAWYER_MAPPER = (rs, row) -> new Lawyer(
            rs.getString("lawyer_id"),
            rs.getString("full_name"),
            rs.getString("mobile"),
            rs.getString("email"),
            rs.getString("bar_council"),
            rs.getString("enrollment_no"),
            rs.getBoolean("bar_verified"),
            rs.getTimestamp("bar_verified_at") != null ? rs.getTimestamp("bar_verified_at").toInstant() : null,
            LawyerStatus.valueOf(rs.getString("status").toUpperCase()),
            rs.getBoolean("kyc_admin_approved"),
            rs.getTimestamp("kyc_approved_at") != null ? rs.getTimestamp("kyc_approved_at").toInstant() : null,
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;

    /** Constructs ApproveLawyerHandler with required dependencies. */
    public ApproveLawyerHandler(DbClient dbClient, JwtService jwtService, AuditWriter auditWriter) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
    }

    /** POST /auth/lawyer/approve — admin sets a pending lawyer to active. */
    @PostMapping("/approve")
    public ResponseEntity<ApiResponse<Map<String, String>>> approveLawyer(
            @RequestBody @Valid ApproveLawyerRequest request,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.ADMIN) {
            throw AppException.forbidden();
        }
        String adminId = jwt.sub();

        List<Lawyer> lawyers = dbClient.query(SELECT_LAWYER, LAWYER_MAPPER, request.lawyerId());
        if (lawyers.isEmpty()) {
            throw AppException.notFound("lawyer");
        }
        Lawyer lawyer = lawyers.get(0);

        if (lawyer.status() == LawyerStatus.ACTIVE) {
            throw AppException.conflict("Lawyer is already approved");
        }
        if (lawyer.status() == LawyerStatus.SUSPENDED || lawyer.status() == LawyerStatus.REMOVED) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                    "Lawyer account cannot be approved in current state");
        }

        Instant now = Instant.now();
        dbClient.execute(UPDATE_LAWYER_ACTIVE, now, now, lawyer.lawyerId());
        dbClient.execute(UPDATE_KYC_FLAG_VERIFIED, now, lawyer.lawyerId());

        auditWriter.write(AuditWritePayload.builder(AuditEventType.LAWYER_ADMIN_APPROVED, AuditResult.SUCCESS)
                .actorId(adminId).actorType(PartyType.ADMIN).targetId(lawyer.lawyerId()).build());

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                Map.of("lawyerId", lawyer.lawyerId(), "status", "active"), requestId));
    }
}
