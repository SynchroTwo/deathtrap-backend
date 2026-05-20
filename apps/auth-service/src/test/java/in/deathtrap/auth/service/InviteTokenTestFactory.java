package in.deathtrap.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Test-only helper that reproduces the UI's client-side invite-token construction so the
 * backend {@link InviteTokenVerifier} can be exercised self-consistently.
 *
 * <p>Mirrors {@code src/nominees/inviteToken.ts}:
 * <pre>
 *   canonical  = canonicalJson(payload)              // sorted keys, no whitespace
 *   inner      = SHA-256(canonical)
 *   signature  = base64( ECDSA_P256_P1363( SHA-256(inner) ) )   // WebCrypto double-hashes
 *   token      = base64url( utf8( canonicalJson({payload, signature}) ) )
 * </pre>
 * A {@link TreeMap} provides the sorted-key canonical ordering; Jackson serializes map
 * entries in iteration order with no whitespace, so the nested payload inside the signed
 * wrapper is byte-identical to the standalone canonical payload — exactly the invariant the
 * verifier relies on.
 */
public final class InviteTokenTestFactory {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private InviteTokenTestFactory() {}

    /** Generates a P-256 keypair, matching the creator's ECDSA signing key. */
    public static KeyPair generateEcKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Encodes a public key as SPKI PEM (what GET /auth/creator/:id/pubkey returns). */
    public static String spkiPem(PublicKey pub) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(pub.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
    }

    /** A canonical sample InviteToken payload with the standard 10 fields. */
    public static Map<String, Object> samplePayload(String creatorId, String nomineeId, Instant expiresAt) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("schemaVersion", 1);
        p.put("purpose", "creator-invite-nominee");
        p.put("creatorId", creatorId);
        p.put("creatorName", "Alice Creator");
        p.put("nomineeId", nomineeId);
        p.put("fullName", "Bob Nominee");
        p.put("email", "bob@example.com");
        p.put("mobile", null);
        p.put("expiresAt", expiresAt.toString());
        p.put("nonce", "nonce-abc-123");
        return p;
    }

    /** Builds a fully signed invite token from the given payload fields. */
    public static String buildToken(PrivateKey signingKey, Map<String, Object> payloadFields) {
        try {
            TreeMap<String, Object> payload = new TreeMap<>(payloadFields);
            String canonical = MAPPER.writeValueAsString(payload);
            byte[] inner = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));

            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(signingKey);
            signer.update(inner);
            String signatureB64 = Base64.getEncoder().encodeToString(signer.sign());

            TreeMap<String, Object> signed = new TreeMap<>();
            signed.put("payload", payload);
            signed.put("signature", signatureB64);
            String tokenJson = MAPPER.writeValueAsString(signed);
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tokenJson.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Builds a tampered token: signs {@code signedPayload} but ships {@code shippedPayload}
     * in the wrapper, so the signature no longer matches the transported bytes.
     */
    public static String buildTamperedToken(PrivateKey signingKey,
            Map<String, Object> signedPayload, Map<String, Object> shippedPayload) {
        try {
            TreeMap<String, Object> signedTree = new TreeMap<>(signedPayload);
            byte[] inner = MessageDigest.getInstance("SHA-256")
                    .digest(MAPPER.writeValueAsString(signedTree).getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(signingKey);
            signer.update(inner);
            String signatureB64 = Base64.getEncoder().encodeToString(signer.sign());

            TreeMap<String, Object> wrapper = new TreeMap<>();
            wrapper.put("payload", new TreeMap<>(shippedPayload));
            wrapper.put("signature", signatureB64);
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MAPPER.writeValueAsString(wrapper).getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
