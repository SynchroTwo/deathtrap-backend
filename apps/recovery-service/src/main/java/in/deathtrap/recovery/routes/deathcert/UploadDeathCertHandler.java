package in.deathtrap.recovery.routes.deathcert;

import in.deathtrap.common.audit.AuditWritePayload;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiResponse;
import in.deathtrap.common.types.dto.JwtPayload;
import in.deathtrap.common.types.dto.UploadDeathCertRequest;
import in.deathtrap.common.types.enums.AuditEventType;
import in.deathtrap.common.types.enums.AuditResult;
import in.deathtrap.common.types.enums.PartyType;
import in.deathtrap.recovery.config.JwtService;
import jakarta.validation.Valid;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/** E006 Phase 1 Deploy B Chunk 1 — death certificate upload + confirmation-window dispatch.
 *  See docs/ClaudeOutput/E006_BACKEND_CONTRACT.md §8 and §9. */
@RestController
@RequestMapping("/recovery/death-cert")
public class UploadDeathCertHandler {

    private static final Logger log = LoggerFactory.getLogger(UploadDeathCertHandler.class);

    private static final long MAX_BYTES = 10L * 1024L * 1024L; // 10 MB hard cap per V018 CHECK
    private static final int DEFAULT_WINDOW_HOURS = 24;
    private static final int LAWYER_WINDOW_HOURS = 168;
    private static final List<String> ALLOWED_MIMES = List.of("image/jpeg", "image/png", "application/pdf");

    private static final String SELECT_NOMINEE_OWNED =
            "SELECT 1 FROM nominees WHERE nominee_id = ? AND creator_id = ? " +
            "AND status = 'active'::nominee_status_enum LIMIT 1";
    private static final String SELECT_NOMINEE_TRUSTEE =
            "SELECT 1 FROM nominees WHERE nominee_id = ? AND creator_id = ? " +
            "AND status = 'active'::nominee_status_enum AND is_trustee = TRUE LIMIT 1";
    private static final String SELECT_ACTIVE_BLOB_SHAPE =
            "SELECT recovery_shape FROM recovery_blobs WHERE creator_id = ? AND status = 'active' LIMIT 1";
    private static final String SELECT_LAWYER_DESIGNATED =
            "SELECT assigned_lawyer_id FROM locker_meta WHERE user_id = ? LIMIT 1";
    private static final String SELECT_ACTIVE_WINDOW =
            "SELECT window_id, status, cooloff_until, expires_at, lawyer_expires_at " +
            "FROM confirmation_window WHERE creator_id = ? " +
            "ORDER BY started_at DESC LIMIT 1";
    private static final String SELECT_LATEST_CYCLE =
            "SELECT COALESCE(MAX(cycle_number), 0) FROM confirmation_window WHERE creator_id = ?";

    private static final String INSERT_CERT =
            "INSERT INTO death_cert_uploads (cert_id, creator_id, uploader_party_id, uploader_party_type, " +
            "s3_key, mime_type, size_bytes, content_hash_sha256, uploaded_at) " +
            "VALUES (?, ?, ?, ?::party_type_enum, ?, ?, ?, ?, NOW())";
    private static final String INSERT_WINDOW =
            "INSERT INTO confirmation_window (window_id, creator_id, first_cert_id, cycle_number, " +
            "window_hours, lawyer_designated, started_at, expires_at, lawyer_expires_at, status) " +
            "VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?, 'pending')";

    private static final RowMapper<Integer> ONE_MAPPER = (rs, row) -> 1;
    private static final RowMapper<String> STRING_MAPPER = (rs, row) -> rs.getString(1);
    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);
    private static final RowMapper<ActiveWindow> ACTIVE_WINDOW_MAPPER = (rs, row) -> new ActiveWindow(
            rs.getString("window_id"),
            rs.getString("status"),
            Optional.ofNullable(rs.getTimestamp("cooloff_until")).map(Timestamp::toInstant).orElse(null),
            Optional.ofNullable(rs.getTimestamp("expires_at")).map(Timestamp::toInstant).orElse(null),
            Optional.ofNullable(rs.getTimestamp("lawyer_expires_at")).map(Timestamp::toInstant).orElse(null));

    private final DbClient dbClient;
    private final JwtService jwtService;
    private final AuditWriter auditWriter;
    private final S3Client s3Client;

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    @Value("${KMS_KEY_ID:}")
    private String kmsKeyId;

    @Value("${ENVIRONMENT:local}")
    private String environment;

    public UploadDeathCertHandler(DbClient dbClient, JwtService jwtService,
            AuditWriter auditWriter, S3Client s3Client) {
        this.dbClient = dbClient;
        this.jwtService = jwtService;
        this.auditWriter = auditWriter;
        this.s3Client = s3Client;
    }

    /** POST /recovery/death-cert — see contract §8. */
    @PostMapping
    public ResponseEntity<ApiResponse<UploadDeathCertResponse>> uploadCert(
            @RequestBody @Valid UploadDeathCertRequest request,
            @RequestHeader("Authorization") String authHeader) {

        JwtPayload jwt = validateNomineeJwt(authHeader);
        String uploaderId = jwt.sub();
        String creatorId = request.creatorId();

        // 1. Mime check
        if (!ALLOWED_MIMES.contains(request.mimeType())) {
            throw AppException.validationFailed(Map.of(
                    "field", "mimeType",
                    "allowed", ALLOWED_MIMES,
                    "got", request.mimeType()));
        }

        // 2. Authorization — model-dependent.
        String shape = dbClient.queryOne(SELECT_ACTIVE_BLOB_SHAPE, STRING_MAPPER, creatorId)
                .orElseThrow(() -> AppException.notFound("recovery_blob"));
        if ("sequential".equals(shape)) {
            // Model A: caller must be a trustee.
            if (dbClient.queryOne(SELECT_NOMINEE_TRUSTEE, ONE_MAPPER, uploaderId, creatorId).isEmpty()) {
                throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                        "Only trustees can upload a death cert for a Model A locker");
            }
        } else {
            // Model B (parallel) or any other shape: any active nominee linked to creator.
            if (dbClient.queryOne(SELECT_NOMINEE_OWNED, ONE_MAPPER, uploaderId, creatorId).isEmpty()) {
                throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                        "Caller is not an active nominee for this creator");
            }
        }

        // 3. Decode + size + hash verification.
        byte[] certBytes = decodeAndValidateCert(request);

        // 4. Look up any prior window — decide windowAction.
        Optional<ActiveWindow> existingWindowOpt = dbClient.queryOne(
                SELECT_ACTIVE_WINDOW, ACTIVE_WINDOW_MAPPER, creatorId);

        Instant now = Instant.now();
        String certId = CsprngUtil.randomUlid();
        String s3Key = "recovery/death-certs/" + creatorId + "/" + certId;

        WindowDispatchPlan plan = planWindowDispatch(existingWindowOpt, certId, creatorId, now);

        // 5. Upload to S3 (or skip in dev).
        putToS3OrDev(certId, s3Key, certBytes);

        // 6. Persist within a single transaction so cert + window are consistent.
        dbClient.withTransaction(status -> {
            dbClient.execute(INSERT_CERT,
                    certId, creatorId, uploaderId, PartyType.NOMINEE.name().toLowerCase(),
                    s3Key, request.mimeType(), request.sizeBytes(), request.contentHashSha256());
            if (plan.newWindow != null) {
                NewWindow nw = plan.newWindow;
                dbClient.execute(INSERT_WINDOW,
                        nw.windowId, creatorId, certId, nw.cycleNumber,
                        nw.windowHours, nw.lawyerDesignated,
                        Timestamp.from(nw.expiresAt),
                        nw.lawyerExpiresAt != null ? Timestamp.from(nw.lawyerExpiresAt) : null);
            }
            return null;
        });

        auditWriter.write(AuditWritePayload
                .builder(AuditEventType.DEATH_CERT_UPLOADED, AuditResult.SUCCESS)
                .actorId(uploaderId).actorType(PartyType.NOMINEE).targetId(certId)
                .metadataJson(Map.of(
                        "creatorId", creatorId,
                        "windowAction", plan.windowAction,
                        "sizeBytes", request.sizeBytes(),
                        "cycleNumber", plan.newWindow != null ? plan.newWindow.cycleNumber : 0))
                .build());

        if (plan.newWindow != null) {
            auditWriter.write(AuditWritePayload
                    .builder(AuditEventType.CONFIRMATION_WINDOW_STARTED, AuditResult.SUCCESS)
                    .actorId(uploaderId).actorType(PartyType.NOMINEE).targetId(plan.newWindow.windowId)
                    .metadataJson(Map.of(
                            "creatorId", creatorId,
                            "cycleNumber", plan.newWindow.cycleNumber,
                            "windowHours", plan.newWindow.windowHours,
                            "lawyerDesignated", plan.newWindow.lawyerDesignated))
                    .build());
            // Phase 1 ships email-only notifications via SES; SES template wiring lands in a
            // follow-up commit once UI provides the notification copy file. The window itself
            // is already actionable via the action-link endpoints (POST /recovery/window/...).
            log.info("Confirmation window started: windowId={} creatorId={} cycle={} hours={} lawyer={}",
                    plan.newWindow.windowId, creatorId, plan.newWindow.cycleNumber,
                    plan.newWindow.windowHours, plan.newWindow.lawyerDesignated);
        }

        log.info("Death cert uploaded: certId={} creatorId={} uploader={} windowAction={}",
                certId, creatorId, uploaderId, plan.windowAction);

        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.status(201).body(ApiResponse.ok(
                new UploadDeathCertResponse(
                        certId,
                        plan.newWindow != null ? plan.newWindow.windowId : null,
                        plan.windowAction,
                        plan.newWindow != null ? plan.newWindow.expiresAt : null,
                        plan.newWindow != null ? plan.newWindow.lawyerExpiresAt : null),
                requestId));
    }

    /** Decides what the current cert upload does to any existing confirmation window. */
    private WindowDispatchPlan planWindowDispatch(Optional<ActiveWindow> existingOpt,
            String certId, String creatorId, Instant now) {
        if (existingOpt.isEmpty()) {
            return new WindowDispatchPlan("new_cycle", buildNewWindow(creatorId, certId, 1, now));
        }
        ActiveWindow existing = existingOpt.get();
        return switch (existing.status) {
            case "pending"   -> new WindowDispatchPlan("logged_existing_cycle", null);
            case "confirmed" -> new WindowDispatchPlan("logged_phase5", null);
            case "objected", "lawyer_silent", "expired" -> {
                if (existing.cooloffUntil != null && existing.cooloffUntil.isAfter(now)) {
                    throw new AppException(ErrorCode.CONFLICT,
                            "Recovery is in cooloff until " + existing.cooloffUntil);
                }
                int nextCycle = dbClient.queryOne(SELECT_LATEST_CYCLE, INT_MAPPER, creatorId).orElse(0) + 1;
                yield new WindowDispatchPlan("new_cycle",
                        buildNewWindow(creatorId, certId, nextCycle, now));
            }
            default -> throw new AppException(ErrorCode.INTERNAL_ERROR,
                    "Unknown confirmation_window status: " + existing.status);
        };
    }

    private NewWindow buildNewWindow(String creatorId, String certId, int cycleNumber, Instant now) {
        boolean lawyerDesignated = dbClient.queryOne(SELECT_LAWYER_DESIGNATED, STRING_MAPPER, creatorId)
                .map(s -> s != null && !s.isBlank()).orElse(false);
        Instant expiresAt = now.plus(DEFAULT_WINDOW_HOURS, ChronoUnit.HOURS);
        Instant lawyerExpiresAt = lawyerDesignated ? now.plus(LAWYER_WINDOW_HOURS, ChronoUnit.HOURS) : null;
        return new NewWindow(CsprngUtil.randomUlid(), cycleNumber, DEFAULT_WINDOW_HOURS,
                lawyerDesignated, expiresAt, lawyerExpiresAt);
    }

    private byte[] decodeAndValidateCert(UploadDeathCertRequest request) {
        if (request.sizeBytes() > MAX_BYTES) {
            throw AppException.validationFailed(Map.of(
                    "field", "sizeBytes",
                    "max", MAX_BYTES,
                    "got", request.sizeBytes()));
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(request.certB64());
        } catch (IllegalArgumentException ex) {
            throw AppException.validationFailed(Map.of("field", "certB64", "message", "Not valid base64"));
        }
        if (bytes.length != request.sizeBytes()) {
            throw AppException.validationFailed(Map.of(
                    "field", "sizeBytes",
                    "message", "Decoded length " + bytes.length + " != declared " + request.sizeBytes()));
        }
        String actualHash = Sha256Util.hashHex(bytes);
        if (!actualHash.equalsIgnoreCase(request.contentHashSha256())) {
            throw AppException.validationFailed(Map.of(
                    "field", "contentHashSha256",
                    "message", "Computed hash does not match declared hash"));
        }
        return bytes;
    }

    private void putToS3OrDev(String certId, String s3Key, byte[] bytes) {
        if (s3BucketName == null || s3BucketName.isBlank()) {
            log.warn("[DEV] S3 upload skipped for death cert certId={}", certId);
            return;
        }
        PutObjectRequest.Builder builder = PutObjectRequest.builder()
                .bucket(s3BucketName)
                .key(s3Key)
                .serverSideEncryption(ServerSideEncryption.AWS_KMS);
        if (kmsKeyId != null && !kmsKeyId.isBlank()) {
            builder.ssekmsKeyId(kmsKeyId);
        }
        s3Client.putObject(builder.build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(bytes));
    }

    private JwtPayload validateNomineeJwt(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AppException.unauthorized();
        }
        JwtPayload jwt = jwtService.validateToken(authHeader.substring(7));
        if (jwt.partyType() != PartyType.NOMINEE) {
            throw new AppException(ErrorCode.AUTH_FORBIDDEN,
                    "Only nominees can upload a death cert");
        }
        return jwt;
    }

    private record ActiveWindow(String windowId, String status, Instant cooloffUntil,
            Instant expiresAt, Instant lawyerExpiresAt) {}

    private record NewWindow(String windowId, int cycleNumber, int windowHours,
            boolean lawyerDesignated, Instant expiresAt, Instant lawyerExpiresAt) {}

    private record WindowDispatchPlan(String windowAction, NewWindow newWindow) {}

    private record UploadDeathCertResponse(
            String certId,
            String windowId,           // null when no new window was created
            String windowAction,       // 'new_cycle' | 'logged_existing_cycle' | 'logged_phase5'
            Instant expiresAt,
            Instant lawyerExpiresAt
    ) {}
}
