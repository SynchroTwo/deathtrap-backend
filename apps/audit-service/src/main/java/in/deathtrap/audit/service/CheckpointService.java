package in.deathtrap.audit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.deathtrap.audit.rowmapper.AuditCheckpointRowMapper;
import in.deathtrap.audit.rowmapper.AuditCheckpointRowMapper.AuditCheckpoint;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.ChainVerifier.ChainVerifyResult;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/** Runs the daily audit checkpoint: verifies the hash chain, archives to S3, writes a checkpoint row. */
@Service
public class CheckpointService {

    private static final Logger log = LoggerFactory.getLogger(CheckpointService.class);

    private static final String SELECT_LAST_CHECKPOINT =
            "SELECT * FROM audit_hash_checkpoints ORDER BY created_at DESC LIMIT 1";
    private static final String SELECT_ALL_SINCE =
            "SELECT * FROM audit_log ORDER BY created_at ASC, audit_id ASC";
    private static final String SELECT_SINCE_AUDIT =
            "SELECT * FROM audit_log WHERE created_at >= " +
            "(SELECT created_at FROM audit_log WHERE audit_id = ?) " +
            "ORDER BY created_at ASC, audit_id ASC";
    private static final String INSERT_CHECKPOINT =
            "INSERT INTO audit_hash_checkpoints (checkpoint_id, up_to_audit_id, checkpoint_hash, created_at) " +
            "VALUES (?, ?, ?, NOW())";

    @Value("${S3_BUCKET_NAME:}")
    private String s3BucketName;

    private final DbClient db;
    private final ChainVerifier verifier;
    private final S3Client s3;
    private final ObjectMapper mapper;

    /** Constructs CheckpointService with required dependencies. */
    public CheckpointService(DbClient db, ChainVerifier verifier, S3Client s3, ObjectMapper mapper) {
        this.db = db;
        this.verifier = verifier;
        this.s3 = s3;
        this.mapper = mapper;
    }

    /** Verifies the chain since the last checkpoint, archives entries to S3, and writes a new checkpoint row. */
    public void runDailyCheckpoint() {
        log.info("Audit checkpoint starting: {}", Instant.now());

        Optional<AuditCheckpoint> lastCheckpoint = db.queryOne(
                SELECT_LAST_CHECKPOINT, AuditCheckpointRowMapper.INSTANCE);

        String fromAuditId = lastCheckpoint.map(AuditCheckpoint::upToAuditId).orElse(null);

        ChainVerifyResult result = verifier.verify(fromAuditId);

        if (!result.valid()) {
            log.error("CRITICAL: Audit chain integrity failure detected. firstInvalidAuditId={}",
                    result.firstInvalidAuditId());
            emitIntegrityFailureMetric();
        }

        List<AuditLogRow> entriesToArchive = fetchEntriesSince(fromAuditId);

        if (entriesToArchive.isEmpty()) {
            log.info("Audit checkpoint: no new entries since last checkpoint, skipping.");
            return;
        }

        if (!s3BucketName.isBlank()) {
            archiveToS3(entriesToArchive, result);
        }

        String lastAuditId = entriesToArchive.get(entriesToArchive.size() - 1).auditId();
        String lastEntryHash = entriesToArchive.get(entriesToArchive.size() - 1).entryHash();
        db.execute(INSERT_CHECKPOINT, CsprngUtil.randomUlid(), lastAuditId, lastEntryHash);

        log.info("Audit checkpoint complete: entriesChecked={} chainValid={} archived={}",
                result.entriesChecked(), result.valid(), entriesToArchive.size());
    }

    private List<AuditLogRow> fetchEntriesSince(String fromAuditId) {
        return fromAuditId == null
                ? db.query(SELECT_ALL_SINCE, AuditLogRowMapper.INSTANCE)
                : db.query(SELECT_SINCE_AUDIT, AuditLogRowMapper.INSTANCE, fromAuditId);
    }

    private void archiveToS3(List<AuditLogRow> entries, ChainVerifyResult result) {
        try {
            String key = "audit/checkpoints/" + Instant.now().toString().substring(0, 10) +
                         "/" + CsprngUtil.randomUlid() + ".json";
            byte[] data = mapper.writeValueAsBytes(
                    Map.of("entries", entries, "chainValid", result.valid()));
            PutObjectRequest req = PutObjectRequest.builder().bucket(s3BucketName).key(key).build();
            s3.putObject(req, RequestBody.fromBytes(data));
            log.info("Audit archive written to S3: key={}", key);
        } catch (Exception e) {
            log.error("Failed to archive audit to S3: error={}", e.getMessage(), e);
        }
    }

    private void emitIntegrityFailureMetric() {
        log.error("AUDIT_INTEGRITY_FAILURE metric emitted");
    }
}
