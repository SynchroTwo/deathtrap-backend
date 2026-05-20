package in.deathtrap.auth.service;

import in.deathtrap.auth.service.InviteTokenVerifier.ParsedInvite;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Self-consistent crypto tests for {@link InviteTokenVerifier}: a token signed exactly as the
 * UI signs it (see {@link InviteTokenTestFactory}) must verify, and any tamper / wrong key /
 * expiry / bad-purpose must be rejected. Proves the verifier is internally correct; the
 * cross-implementation guarantee comes from the pinned vector in
 * docs/NOMINEE_INVITE_TEST_VECTOR_V1.md once the UI supplies it.
 */
class InviteTokenVerifierTest {

    private static final String CREATOR_ID = "creator-01HZ";
    private static final String NOMINEE_ID = "nominee-01HZ";

    @Test
    void validToken_verifiesAndParsesFields() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        Instant expires = Instant.now().plusSeconds(86_400);
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(),
                InviteTokenTestFactory.samplePayload(CREATOR_ID, NOMINEE_ID, expires));

        ParsedInvite invite = InviteTokenVerifier.verify(token,
                InviteTokenTestFactory.spkiPem(creator.getPublic()));

        assertEquals(1, invite.schemaVersion());
        assertEquals("creator-invite-nominee", invite.purpose());
        assertEquals(CREATOR_ID, invite.creatorId());
        assertEquals(NOMINEE_ID, invite.nomineeId());
        assertEquals("Bob Nominee", invite.fullName());
        assertEquals("bob@example.com", invite.email());
        assertNull(invite.mobile());
        assertEquals("nonce-abc-123", invite.nonce());
    }

    @Test
    void peekCreatorId_returnsCreatorWithoutVerifying() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(),
                InviteTokenTestFactory.samplePayload(CREATOR_ID, NOMINEE_ID,
                        Instant.now().plusSeconds(3600)));

        assertEquals(CREATOR_ID, InviteTokenVerifier.peekCreatorId(token));
    }

    @Test
    void braceInsideStringValue_stillVerifies() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        Map<String, Object> payload = InviteTokenTestFactory.samplePayload(
                CREATOR_ID, NOMINEE_ID, Instant.now().plusSeconds(3600));
        payload.put("fullName", "Bob {the} N\"ominee}");
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(), payload);

        ParsedInvite invite = InviteTokenVerifier.verify(token,
                InviteTokenTestFactory.spkiPem(creator.getPublic()));

        assertEquals("Bob {the} N\"ominee}", invite.fullName());
    }

    @Test
    void tamperedPayload_throwsInviteInvalid() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        Map<String, Object> signed = InviteTokenTestFactory.samplePayload(
                CREATOR_ID, NOMINEE_ID, Instant.now().plusSeconds(3600));
        Map<String, Object> shipped = InviteTokenTestFactory.samplePayload(
                CREATOR_ID, NOMINEE_ID, Instant.now().plusSeconds(3600));
        shipped.put("fullName", "Mallory Attacker");
        String token = InviteTokenTestFactory.buildTamperedToken(
                creator.getPrivate(), signed, shipped);

        AppException ex = assertThrows(AppException.class, () -> InviteTokenVerifier.verify(
                token, InviteTokenTestFactory.spkiPem(creator.getPublic())));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void wrongCreatorKey_throwsInviteInvalid() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        KeyPair impostor = InviteTokenTestFactory.generateEcKeyPair();
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(),
                InviteTokenTestFactory.samplePayload(CREATOR_ID, NOMINEE_ID,
                        Instant.now().plusSeconds(3600)));

        AppException ex = assertThrows(AppException.class, () -> InviteTokenVerifier.verify(
                token, InviteTokenTestFactory.spkiPem(impostor.getPublic())));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void expiredToken_throwsInviteExpired() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(),
                InviteTokenTestFactory.samplePayload(CREATOR_ID, NOMINEE_ID,
                        Instant.now().minusSeconds(3600)));

        AppException ex = assertThrows(AppException.class, () -> InviteTokenVerifier.verify(
                token, InviteTokenTestFactory.spkiPem(creator.getPublic())));
        assertEquals(ErrorCode.AUTH_INVITE_EXPIRED, ex.getErrorCode());
    }

    @Test
    void wrongPurpose_throwsInviteInvalid() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        Map<String, Object> payload = InviteTokenTestFactory.samplePayload(
                CREATOR_ID, NOMINEE_ID, Instant.now().plusSeconds(3600));
        payload.put("purpose", "something-else");
        String token = InviteTokenTestFactory.buildToken(creator.getPrivate(), payload);

        AppException ex = assertThrows(AppException.class, () -> InviteTokenVerifier.verify(
                token, InviteTokenTestFactory.spkiPem(creator.getPublic())));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }

    @Test
    void malformedToken_throwsInviteInvalid() {
        KeyPair creator = InviteTokenTestFactory.generateEcKeyPair();
        AppException ex = assertThrows(AppException.class, () -> InviteTokenVerifier.verify(
                "!!!not-base64url!!!", InviteTokenTestFactory.spkiPem(creator.getPublic())));
        assertEquals(ErrorCode.AUTH_INVITE_INVALID, ex.getErrorCode());
    }
}
