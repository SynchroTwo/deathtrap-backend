package in.deathtrap.audit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import in.deathtrap.audit.rowmapper.AuditCheckpointRowMapper.AuditCheckpoint;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.audit.service.ChainVerifier.ChainVerifyResult;
import in.deathtrap.common.db.DbClient;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for CheckpointService — no Spring context. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"unchecked", "rawtypes"})
class CheckpointServiceTest {

    @Mock private DbClient db;
    @Mock private ChainVerifier verifier;
    @Mock private S3Client s3;

    private CheckpointService service;

    private static final Instant NOW = Instant.parse("2026-05-08T10:00:00.000000Z");

    private static AuditLogRow row(String id, String hash) {
        return new AuditLogRow(id, "USER_REGISTERED", "actor-1", "CREATOR",
                null, null, null, null, "SUCCESS", null, null, null, hash, NOW);
    }

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        service = new CheckpointService(db, verifier, s3, mapper);
    }

    @Test
    void chainValid_writesCheckpointAndArchivesToS3() {
        ReflectionTestUtils.setField(service, "s3BucketName", "my-bucket");
        when(db.queryOne(contains("audit_hash_checkpoints"), any())).thenReturn(Optional.empty());
        when(db.query(contains("audit_log"), any())).thenReturn((List) List.of(row("aid-1", "hash1")));
        when(verifier.verify(null)).thenReturn(new ChainVerifyResult(true, 1, null, NOW, NOW));
        when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());

        service.runDailyCheckpoint();

        verify(db).execute(contains("INSERT INTO audit_hash_checkpoints"), any(), any(), any());
        verify(s3).putObject(any(PutObjectRequest.class), any(RequestBody.class));
    }

    @Test
    void chainInvalid_logsError_checkpointStillWritten() {
        ReflectionTestUtils.setField(service, "s3BucketName", "");
        when(db.queryOne(contains("audit_hash_checkpoints"), any())).thenReturn(Optional.empty());
        when(db.query(contains("audit_log"), any())).thenReturn((List) List.of(row("aid-1", "hash1")));
        when(verifier.verify(null)).thenReturn(
                new ChainVerifyResult(false, 1, "aid-1", NOW, NOW));

        service.runDailyCheckpoint();

        verify(db).execute(contains("INSERT INTO audit_hash_checkpoints"), any(), any(), any());
    }

    @Test
    void s3NotConfigured_skipsArchival_checkpointWritten() {
        ReflectionTestUtils.setField(service, "s3BucketName", "");
        when(db.queryOne(contains("audit_hash_checkpoints"), any())).thenReturn(Optional.empty());
        when(db.query(contains("audit_log"), any())).thenReturn((List) List.of(row("aid-1", "hash1")));
        when(verifier.verify(null)).thenReturn(new ChainVerifyResult(true, 1, null, NOW, NOW));

        service.runDailyCheckpoint();

        verify(s3, never()).putObject(any(PutObjectRequest.class), any(RequestBody.class));
        verify(db).execute(contains("INSERT INTO audit_hash_checkpoints"), any(), any(), any());
    }

    @Test
    void noEntriesSinceLastCheckpoint_skipsArchivalAndCheckpoint() {
        ReflectionTestUtils.setField(service, "s3BucketName", "my-bucket");
        when(db.queryOne(contains("audit_hash_checkpoints"), any())).thenReturn(
                Optional.of(new AuditCheckpoint("cp-1", "aid-prev", "prevhash", NOW)));
        when(verifier.verify("aid-prev")).thenReturn(new ChainVerifyResult(true, 0, null, NOW, NOW));
        when(db.query(contains("audit_log"), any(), any())).thenReturn(List.of());

        service.runDailyCheckpoint();

        verify(s3, never()).putObject(any(PutObjectRequest.class), any(RequestBody.class));
        verify(db, never()).execute(contains("INSERT INTO audit_hash_checkpoints"),
                any(), any(), any());
    }

    @Test
    void s3UploadFails_errorLogged_noExceptionPropagated() {
        ReflectionTestUtils.setField(service, "s3BucketName", "my-bucket");
        when(db.queryOne(contains("audit_hash_checkpoints"), any())).thenReturn(Optional.empty());
        when(db.query(contains("audit_log"), any())).thenReturn((List) List.of(row("aid-1", "hash1")));
        when(verifier.verify(null)).thenReturn(new ChainVerifyResult(true, 1, null, NOW, NOW));
        when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenThrow(new RuntimeException("S3 unavailable"));

        service.runDailyCheckpoint();

        verify(db).execute(contains("INSERT INTO audit_hash_checkpoints"), any(), any(), any());
    }
}
