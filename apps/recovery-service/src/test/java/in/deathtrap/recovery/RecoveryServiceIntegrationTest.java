package in.deathtrap.recovery;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.IntegrationTestBase;
import in.deathtrap.common.types.dto.BlobLayerRequest;
import in.deathtrap.common.types.dto.InitiateSessionRequest;
import in.deathtrap.common.types.dto.StoreBlobRequest;
import in.deathtrap.recovery.config.JwtService;
import in.deathtrap.recovery.routes.blob.StoreBlobHandler;
import in.deathtrap.recovery.routes.session.InitiateSessionHandler;
import in.deathtrap.recovery.service.BlobRebuildLogService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import software.amazon.awssdk.services.s3.S3Client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;

/** Integration tests — recovery-service handlers against a real PostgreSQL container. */
class RecoveryServiceIntegrationTest extends IntegrationTestBase {

    private static final String JWT_SECRET = "test-secret-key-for-integration-tests-minimum32b";
    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final JwtService RECOVERY_JWT = new JwtService(JWT_SECRET);
    private static final AuditWriter AUDIT = new AuditWriter(db);
    private static final BlobRebuildLogService REBUILD_LOG = new BlobRebuildLogService(db);
    // S3 is skipped when bucket name is blank — use null/mock client
    private static final S3Client S3_MOCK = mock(S3Client.class);

    @Override
    protected String[] tablesToClean() {
        return new String[]{
            "audit_log", "blob_rebuild_log", "recovery_peel_events", "recovery_sessions",
            "recovery_blob_layers", "recovery_blobs", "trigger_events",
            "nominees", "party_public_keys", "party_salts",
            "encrypted_privkey_blobs", "sessions", "users"
        };
    }

    @Test
    void storeBlob_insertsBlobAndLayerRows() {
        String creatorId = insertUser("+919111111111", "blob-store@example.com");
        String nomineeId = insertUser("+919222222222", "nominee-blob@example.com");
        String pubkeyId = insertActivePubkey(nomineeId, "nominee");

        String creatorToken = issueJwt(creatorId, "CREATOR");
        var handler = buildStoreBlobHandler();
        var req = new StoreBlobRequest(
                "encryptedBlobBase64==",
                List.of(new BlobLayerRequest(nomineeId, "nominee", pubkeyId, "fp-nominee-001", 1)),
                "initial_setup");

        ResponseEntity<?> resp = handler.storeBlob(req, "Bearer " + creatorToken);

        assertEquals(201, resp.getStatusCode().value());

        List<Map<String, Object>> blobs = jdbc.queryForList(
                "SELECT blob_id, layer_count FROM recovery_blobs WHERE creator_id = ?", creatorId);
        assertEquals(1, blobs.size(), "One recovery_blobs row should exist");
        assertEquals(1, ((Number) blobs.get(0).get("layer_count")).intValue());

        String blobId = (String) blobs.get(0).get("blob_id");
        List<Map<String, Object>> layers = jdbc.queryForList(
                "SELECT * FROM recovery_blob_layers WHERE blob_id = ?", blobId);
        assertEquals(1, layers.size(), "One recovery_blob_layers row should exist");
        assertEquals(nomineeId, layers.get(0).get("party_id"));
    }

    @Test
    void initiateSession_insertsSessionRow() {
        String creatorId = insertUser("+919333333333", "init-session@example.com");
        String nomineeId = insertUser("+919444444444", "nom-session@example.com");
        String pubkeyId = insertActivePubkey(nomineeId, "nominee");
        String triggerId = insertApprovedTrigger(creatorId);

        // Store a blob first (session requires active recovery blob)
        String creatorToken = issueJwt(creatorId, "CREATOR");
        buildStoreBlobHandler().storeBlob(
                new StoreBlobRequest(
                        "encBlobB64==",
                        List.of(new BlobLayerRequest(nomineeId, "nominee", pubkeyId, "fp-nom", 1)),
                        "initial_setup"),
                "Bearer " + creatorToken);

        // Nominee initiates recovery session
        String nomineeToken = issueJwt(nomineeId, "NOMINEE");
        var handler = new InitiateSessionHandler(db, RECOVERY_JWT, AUDIT);
        ResponseEntity<?> resp = handler.initiateSession(
                new InitiateSessionRequest(creatorId), "Bearer " + nomineeToken);

        assertEquals(201, resp.getStatusCode().value());

        List<Map<String, Object>> sessions = jdbc.queryForList(
                "SELECT creator_id, trigger_id, status FROM recovery_sessions WHERE creator_id = ?",
                creatorId);
        assertFalse(sessions.isEmpty(), "A recovery_sessions row should be created");
        assertEquals("initiated", sessions.get(0).get("status"));
        assertEquals(triggerId, sessions.get(0).get("trigger_id"));
    }

    private StoreBlobHandler buildStoreBlobHandler() {
        var handler = new StoreBlobHandler(db, RECOVERY_JWT, AUDIT, S3_MOCK, REBUILD_LOG);
        // S3_BUCKET_NAME is left blank (not injected) so S3 upload is skipped in dev mode
        return handler;
    }

    private String insertUser(String mobile, String email) {
        String userId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        jdbc.update(
                "INSERT INTO users (user_id, full_name, date_of_birth, mobile, email, " +
                "kyc_status, status, inactivity_trigger_months, created_at, updated_at) " +
                "VALUES (?, 'Test User', '1990-01-01', ?, ?, 'verified'::kyc_status_enum, " +
                "'active'::user_status_enum, 12, ?, ?)",
                userId, mobile, email, now, now);
        return userId;
    }

    private String insertActivePubkey(String partyId, String partyType) {
        String pubkeyId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        jdbc.update(
                "INSERT INTO party_public_keys (pubkey_id, party_id, party_type, key_type, " +
                "public_key_pem, key_fingerprint, version, is_active, activated_at, created_at) " +
                "VALUES (?, ?, ?::party_type_enum, 'ecdh_p256'::key_type_enum, ?, ?, 1, true, ?, ?)",
                pubkeyId, partyId, partyType,
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                "fp-" + partyType + "-001", now, now);
        return pubkeyId;
    }

    private String insertApprovedTrigger(String creatorId) {
        String triggerId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        jdbc.update(
                "INSERT INTO trigger_events (trigger_id, creator_id, status, threshold, " +
                "sources_met, created_at, updated_at) " +
                "VALUES (?, ?, 'approved'::trigger_status_enum, 1, 1, ?, ?)",
                triggerId, creatorId, now, now);
        return triggerId;
    }

    private String issueJwt(String partyId, String partyType) {
        return Jwts.builder()
                .subject(partyId)
                .id(CsprngUtil.randomUlid())
                .claim("partyType", partyType)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000L))
                .signWith(SIGNING_KEY)
                .compact();
    }
}
