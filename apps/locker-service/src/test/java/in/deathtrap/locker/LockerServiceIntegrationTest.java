package in.deathtrap.locker;

import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.IntegrationTestBase;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.dto.NomineeAssignRequest;
import in.deathtrap.locker.config.JwtService;
import in.deathtrap.locker.routes.locker.InitLockerHandler;
import in.deathtrap.locker.routes.nominee.AssignNomineeHandler;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Integration tests — locker-service handlers against a real PostgreSQL container. */
class LockerServiceIntegrationTest extends IntegrationTestBase {

    private static final String JWT_SECRET = "test-secret-key-for-integration-tests-minimum32b";
    private static final SecretKey SIGNING_KEY =
            Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final JwtService LOCKER_JWT = new JwtService(JWT_SECRET);
    private static final AuditWriter AUDIT = new AuditWriter(db);

    @Override
    protected String[] tablesToClean() {
        return new String[]{
            "audit_log", "nominee_assignments", "asset_index", "locker_meta",
            "nominees", "party_public_keys", "party_salts",
            "encrypted_privkey_blobs", "sessions", "users"
        };
    }

    @Test
    void initLocker_createsLockerMetaAnd24AssetRows() {
        String creatorId = insertUser("+911111111111", "locker-init@example.com");
        String token = issueCreatorJwt(creatorId);

        var handler = new InitLockerHandler(db, LOCKER_JWT, AUDIT);
        ResponseEntity<?> resp = handler.initLocker("Bearer " + token);

        assertEquals(201, resp.getStatusCode().value());

        List<Map<String, Object>> lockers = jdbc.queryForList(
                "SELECT locker_id FROM locker_meta WHERE user_id = ?", creatorId);
        assertEquals(1, lockers.size(), "One locker_meta row should be created");

        String lockerId = (String) lockers.get(0).get("locker_id");
        int assetCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM asset_index WHERE locker_id = ?", Integer.class, lockerId);
        assertEquals(24, assetCount, "24 asset_index rows should be created");
    }

    @Test
    void initLocker_twice_throwsConflict() {
        String creatorId = insertUser("+912222222222", "locker-dup@example.com");
        String token = issueCreatorJwt(creatorId);

        var handler = new InitLockerHandler(db, LOCKER_JWT, AUDIT);
        handler.initLocker("Bearer " + token);

        AppException ex = assertThrows(AppException.class,
                () -> handler.initLocker("Bearer " + token));
        assertEquals(ErrorCode.CONFLICT, ex.getErrorCode());
    }

    @Test
    void assignNominee_insertsAssignmentRow() {
        String creatorId = insertUser("+913333333333", "assign@example.com");
        String nomineeId = insertActiveNominee(creatorId, "+914444444444", "nominee@example.com");
        String token = issueCreatorJwt(creatorId);

        var initHandler = new InitLockerHandler(db, LOCKER_JWT, AUDIT);
        initHandler.initLocker("Bearer " + token);

        String assetId = jdbc.queryForObject(
                "SELECT a.asset_id FROM asset_index a JOIN locker_meta m ON a.locker_id = m.locker_id " +
                "WHERE m.user_id = ? LIMIT 1",
                String.class, creatorId);

        var assignHandler = new AssignNomineeHandler(db, LOCKER_JWT, AUDIT);
        ResponseEntity<?> resp = assignHandler.assignNominee(
                new NomineeAssignRequest(assetId, nomineeId), "Bearer " + token);

        assertEquals(201, resp.getStatusCode().value());
        int count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM nominee_assignments WHERE asset_id = ? AND nominee_id = ?",
                Integer.class, assetId, nomineeId);
        assertEquals(1, count);
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

    private String insertActiveNominee(String creatorId, String mobile, String email) {
        String nomineeId = CsprngUtil.randomUlid();
        Instant now = Instant.now();
        jdbc.update(
                "INSERT INTO nominees (nominee_id, creator_id, full_name, mobile, email, " +
                "relationship, status, created_at, updated_at) " +
                "VALUES (?, ?, 'Nominee Name', ?, ?, 'spouse', 'active'::nominee_status_enum, ?, ?)",
                nomineeId, creatorId, mobile, email, now, now);
        return nomineeId;
    }

    private String issueCreatorJwt(String creatorId) {
        return Jwts.builder()
                .subject(creatorId)
                .id(CsprngUtil.randomUlid())
                .claim("partyType", "CREATOR")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000L))
                .signWith(SIGNING_KEY)
                .compact();
    }
}
