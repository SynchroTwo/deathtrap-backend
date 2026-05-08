package in.deathtrap.auth;

import in.deathtrap.auth.config.JwtService;
import in.deathtrap.auth.routes.creator.RegisterHandler;
import in.deathtrap.auth.routes.otp.SendOtpHandler;
import in.deathtrap.auth.routes.otp.VerifyOtpHandler;
import in.deathtrap.common.audit.AuditWriter;
import in.deathtrap.common.crypto.HibpClient;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.db.IntegrationTestBase;
import in.deathtrap.common.types.dto.RegisterCreatorRequest;
import in.deathtrap.common.types.dto.SendOtpRequest;
import in.deathtrap.common.types.dto.VerifyOtpRequest;
import in.deathtrap.common.types.enums.OtpPurpose;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Integration tests — auth-service handlers against a real PostgreSQL container. */
class AuthServiceIntegrationTest extends IntegrationTestBase {

    private static final String JWT_SECRET = "test-secret-key-for-integration-tests-minimum32b";
    private static final JwtService JWT = new JwtService(JWT_SECRET);
    private static final AuditWriter AUDIT = new AuditWriter(db);

    // Bypasses HIBP network check for test environment
    private static final HibpClient NO_OP_HIBP = new HibpClient() {
        @Override
        public void checkPassphrase(String prefix, String suffix, boolean clientFlag) {}
    };

    @Override
    protected String[] tablesToClean() {
        return new String[]{
            "audit_log", "otp_log", "revoked_tokens", "sessions",
            "kyc_flags", "encrypted_privkey_blobs", "party_public_keys",
            "party_salts", "nominees", "users"
        };
    }

    @Test
    void sendOtp_insertsTwoOtpRows() {
        var handler = new SendOtpHandler(db, AUDIT);
        var req = new SendOtpRequest("+919876543210", "otp@example.com", OtpPurpose.REGISTRATION);

        ResponseEntity<?> resp = handler.sendOtp(req);

        assertEquals(200, resp.getStatusCode().value());
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM otp_log WHERE party_id = '+919876543210'");
        assertEquals(2, rows.size(), "Expected sms + email OTP rows");
    }

    @Test
    void verifyOtp_marksRowsVerifiedAndReturnsToken() {
        String partyId = "+910000000001";
        String knownOtp = "123456";
        String hash = Sha256Util.hashHex(knownOtp);
        Instant expiry = Instant.now().plusSeconds(600);
        Instant now = Instant.now();

        jdbc.update(
                "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, " +
                "attempts, verified, expires_at, created_at) " +
                "VALUES (?, ?, 'creator'::party_type_enum, 'sms'::otp_channel_enum, " +
                "'registration'::otp_purpose_enum, ?, 0, false, ?, ?)",
                "OTP-SMS-01", partyId, hash, expiry, now);
        jdbc.update(
                "INSERT INTO otp_log (otp_id, party_id, party_type, channel, purpose, otp_hash, " +
                "attempts, verified, expires_at, created_at) " +
                "VALUES (?, ?, 'creator'::party_type_enum, 'email'::otp_channel_enum, " +
                "'registration'::otp_purpose_enum, ?, 0, false, ?, ?)",
                "OTP-EMAIL-01", partyId, hash, expiry, now);

        var handler = new VerifyOtpHandler(db, JWT, AUDIT);
        var req = new VerifyOtpRequest(partyId, knownOtp, knownOtp, OtpPurpose.REGISTRATION);
        ResponseEntity<?> resp = handler.verifyOtp(req);

        assertEquals(200, resp.getStatusCode().value());
        Boolean smsVerified = jdbc.queryForObject(
                "SELECT verified FROM otp_log WHERE otp_id = 'OTP-SMS-01'", Boolean.class);
        Boolean emailVerified = jdbc.queryForObject(
                "SELECT verified FROM otp_log WHERE otp_id = 'OTP-EMAIL-01'", Boolean.class);
        assertTrue(smsVerified, "SMS OTP row should be marked verified");
        assertTrue(emailVerified, "Email OTP row should be marked verified");
    }

    @Test
    void registerCreator_insertsUserSaltPubkeyAndPrivkeyRows() {
        String mobile = "+919999999999";
        String email = "register@example.com";
        String verifiedToken = JWT.issueVerifiedToken(mobile, OtpPurpose.REGISTRATION);

        var handler = new RegisterHandler(db, JWT, AUDIT, NO_OP_HIBP);
        var req = validRegisterRequest(mobile, email);
        ResponseEntity<?> resp = handler.register(req, "Bearer " + verifiedToken);

        assertEquals(201, resp.getStatusCode().value());

        List<Map<String, Object>> users = jdbc.queryForList(
                "SELECT user_id FROM users WHERE mobile = ?", mobile);
        assertEquals(1, users.size());
        String userId = (String) users.get(0).get("user_id");

        int pubkeys = jdbc.queryForObject(
                "SELECT COUNT(*) FROM party_public_keys WHERE party_id = ?", Integer.class, userId);
        assertEquals(1, pubkeys, "One active pubkey should be created");

        int salts = jdbc.queryForObject(
                "SELECT COUNT(*) FROM party_salts WHERE party_id = ?", Integer.class, userId);
        assertEquals(1, salts, "One salt should be created");

        int privkeys = jdbc.queryForObject(
                "SELECT COUNT(*) FROM encrypted_privkey_blobs WHERE party_id = ?", Integer.class, userId);
        assertEquals(1, privkeys, "One encrypted privkey blob should be created");
    }

    @Test
    void registerCreator_duplicateMobile_throwsConflict() {
        String mobile = "+918888888888";
        String verifiedToken = JWT.issueVerifiedToken(mobile, OtpPurpose.REGISTRATION);

        var handler = new RegisterHandler(db, JWT, AUDIT, NO_OP_HIBP);
        handler.register(validRegisterRequest(mobile, "first@example.com"), "Bearer " + verifiedToken);

        String token2 = JWT.issueVerifiedToken(mobile, OtpPurpose.REGISTRATION);
        try {
            handler.register(validRegisterRequest(mobile, "second@example.com"), "Bearer " + token2);
            throw new AssertionError("Expected duplicate registration exception");
        } catch (in.deathtrap.common.errors.AppException ex) {
            assertEquals(in.deathtrap.common.errors.ErrorCode.AUTH_REGISTRATION_DUPLICATE,
                    ex.getErrorCode());
        }
    }

    private RegisterCreatorRequest validRegisterRequest(String mobile, String email) {
        return new RegisterCreatorRequest(
                "Integration Tester", LocalDate.of(1990, 6, 15),
                mobile, email, "123 Test Street",
                "XXXX1234", "KYC-INT-001",
                "ABCDE", "A".repeat(35), true, 80,
                "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAE\n-----END PUBLIC KEY-----",
                "fp-integration-001",
                "encBase64==", "nonceBase64==", "authTagBase64==",
                "a".repeat(64), 1, 12);
    }
}
