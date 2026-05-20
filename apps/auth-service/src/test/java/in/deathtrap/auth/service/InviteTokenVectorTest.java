package in.deathtrap.auth.service;

import in.deathtrap.auth.service.InviteTokenVerifier.ParsedInvite;
import in.deathtrap.common.crypto.Sha256Util;
import in.deathtrap.common.errors.AppException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Cross-implementation byte-equality test against the UI-generated invite-token vector
 * pinned in docs/NOMINEE_INVITE_TEST_VECTOR_V1.md (inputs mirrored verbatim under
 * src/test/resources/nominee-invite-vector/).
 *
 * <p>If this passes, the backend verifies the exact token the UI's {@code signInviteToken}
 * produced, and the payload bytes it checked the signature over are byte-identical to the
 * UI's {@code canonicalJson(payload)} — i.e. the path-A invite contract agrees across
 * implementations. A failure points directly at the divergence: canonical key ordering,
 * the double-hash, or DER-vs-P1363.
 */
class InviteTokenVectorTest {

    private static String resource(String name) {
        try (InputStream in = InviteTokenVectorTest.class.getClassLoader()
                .getResourceAsStream("nominee-invite-vector/" + name)) {
            assertNotNull(in, "missing test resource: " + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static final String PEM = resource("creator_pubkey.pem");
    private static final String TOKEN = resource("invite_token.txt");
    private static final String CANONICAL = resource("canonical.json");
    private static final String FINGERPRINT = resource("fingerprint.txt");

    @Test
    void pinnedToken_verifies_andPayloadBytesAreByteExact() {
        ParsedInvite invite = InviteTokenVerifier.verify(TOKEN, PEM);

        // Strongest cross-impl assertion: the bytes the backend verified the signature
        // over == the UI's canonicalJson(payload), byte for byte.
        assertEquals(CANONICAL, new String(invite.payloadBytes(), StandardCharsets.UTF_8));

        assertEquals(1, invite.schemaVersion());
        assertEquals("creator-invite-nominee", invite.purpose());
        assertEquals("8f429100-ec91-4a9d-bc9b-cffd940142c8", invite.creatorId());
        assertEquals("Arjun Sharma", invite.creatorName());
        assertEquals("nom_a1b2c3d4", invite.nomineeId());
        assertEquals("Priya Nair", invite.fullName());
        assertEquals("priya@example.com", invite.email());
        assertEquals("+919876543210", invite.mobile());
        assertEquals("f0e1d2c3-b4a5-4697-8899-aabbccddeeff", invite.nonce());
    }

    @Test
    void pinnedPubkey_fingerprintMatchesVector() {
        byte[] der = Base64.getDecoder().decode(
                PEM.replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s", ""));
        assertEquals(FINGERPRINT, Sha256Util.hashHex(der));
    }

    @Test
    void tamperedPinnedToken_rejected() {
        int i = 60; // inside the payload region of the base64url token
        char c = TOKEN.charAt(i);
        String tampered = TOKEN.substring(0, i) + (c == 'A' ? 'B' : 'A') + TOKEN.substring(i + 1);
        assertThrows(AppException.class, () -> InviteTokenVerifier.verify(tampered, PEM));
    }

    @Test
    void backendCanSignSameSchemeWithVectorPrivkey() throws Exception {
        // Using the pinned private key, the backend signs the SAME canonical and the
        // verifier accepts it — proves the keypair + sign/verify scheme agree end to end.
        byte[] pkcs8 = HexFormat.of().parseHex(resource("creator_privkey_pkcs8.hex"));
        PrivateKey priv = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        byte[] inner = Sha256Util.hash(CANONICAL.getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(priv);
        signer.update(inner);
        String sigB64 = Base64.getEncoder().encodeToString(signer.sign());

        String tokenJson = "{\"payload\":" + CANONICAL + ",\"signature\":\"" + sigB64 + "\"}";
        String token = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tokenJson.getBytes(StandardCharsets.UTF_8));

        ParsedInvite invite = InviteTokenVerifier.verify(token, PEM);
        assertEquals("nom_a1b2c3d4", invite.nomineeId());
    }
}
