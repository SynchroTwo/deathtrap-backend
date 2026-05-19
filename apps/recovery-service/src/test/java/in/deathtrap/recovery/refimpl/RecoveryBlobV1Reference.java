package in.deathtrap.recovery.refimpl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test-only Java reference implementation of Recovery Blob Format v1.
 * <p>
 * The deployed backend never performs recovery-blob crypto (per
 * {@code docs/RECOVERY_BLOB_FORMAT.md} §1 and BACKEND_CHANGES §1 — blob
 * arrives opaque, leaves opaque). This class exists <em>only</em> under
 * {@code src/test/java} so we can assert cross-platform byte agreement
 * with the UI reference implementation via the pinned vectors in
 * {@code docs/RECOVERY_TEST_VECTORS_V1.md}.
 * <p>
 * <b>Determinism contract:</b> every source of randomness (envelope salt,
 * ephemeral keypairs, AES-GCM nonces) is supplied as an explicit input.
 * Given identical inputs to UI and Java implementations, the produced
 * {@code encryptedBlobB64} must be byte-identical. Any divergence is a
 * v1 spec violation; the spec doc is the arbiter.
 */
public final class RecoveryBlobV1Reference {

    /** ASN.1 SubjectPublicKeyInfo prefix for an uncompressed P-256 point.
     *  When concatenated with the 65-byte raw SEC1 point (0x04 || X || Y),
     *  yields a 91-byte SPKI DER blob that {@code KeyFactory("EC")} can parse. */
    private static final byte[] P256_SPKI_PREFIX = hex(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200");

    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;

    // No provider registration needed — AES/GCM/NoPadding, HmacSHA256, ECDH, and EC KeyFactory
    // are all in the default JCE provider since Java 8. Avoiding BouncyCastle here keeps the
    // dependency surface of this test-only class minimal.

    private RecoveryBlobV1Reference() {}

    // ---------- public construct / peel API ----------

    /** Recipient (lawyer or nominee) at a single layer position. */
    public record Recipient(
            String partyId,
            String partyType,          // "lawyer" or "nominee"
            byte[] pubkeyRaw65,        // 65-byte uncompressed SEC1 (0x04 || X || Y)
            String keyFingerprint      // lowercase hex SHA-256(SPKI DER)
    ) {}

    /** Ephemeral keypair used for one layer's AAD-bound encryption. */
    public record Ephemeral(
            ECPrivateKey privkey,
            byte[] pubkeyRaw65         // 65-byte uncompressed SEC1
    ) {}

    /** Result of a successful peel. */
    public record PeelResult(
            boolean isInnermost,
            String lockerKeyHex,        // populated only when isInnermost
            byte[] nextEncrypted        // populated only when !isInnermost (= JSON bytes of next layer)
    ) {}

    /** Construct a russian-doll recovery envelope.
     *
     *  @param specVersion       fixed "v1"
     *  @param blobId            UUID v4 lowercase canonical
     *  @param saltBytes         32 random bytes (envelope salt, used as HKDF salt for every layer)
     *  @param lockerKey         32 raw bytes (the innermost payload)
     *  @param innermostCreatedAtIso  ISO 8601 timestamp baked into the innermost JSON
     *  @param recipientsOutermostFirst  ordered list, recipients[0] is the lawyer at layerOrder=1
     *  @param ephemeralsByLayerOrder1   ephemerals[0] is used for layerOrder=1, etc.
     *  @param noncesByLayerOrder1       nonces[0] is used for layerOrder=1, etc.; each 12 bytes
     *  @return the base64-encoded envelope JSON bytes (this is the
     *          {@code encryptedBlobB64} field sent to {@code POST /recovery/blob})
     */
    public static String construct(
            String specVersion,
            String blobId,
            byte[] saltBytes,
            byte[] lockerKey,
            String innermostCreatedAtIso,
            List<Recipient> recipientsOutermostFirst,
            List<Ephemeral> ephemeralsByLayerOrder1,
            List<byte[]> noncesByLayerOrder1) {
        try {
            int n = recipientsOutermostFirst.size();
            if (ephemeralsByLayerOrder1.size() != n || noncesByLayerOrder1.size() != n) {
                throw new IllegalArgumentException("recipients/ephemerals/nonces lists must be same length");
            }

            // Step 1: innermost plaintext bytes.
            byte[] currentPlaintext = buildInnermostJson(lockerKey, innermostCreatedAtIso);

            // Step 2: iterate from innermost (layerOrder=N) outward to outermost (layerOrder=1).
            // The russian doll: each iteration's ciphertext becomes the next iteration's plaintext.
            for (int order = n; order >= 1; order--) {
                Recipient r = recipientsOutermostFirst.get(order - 1);
                Ephemeral e = ephemeralsByLayerOrder1.get(order - 1);
                byte[] nonce = noncesByLayerOrder1.get(order - 1);

                byte[] aad = buildAad(specVersion, blobId, r.partyType(), r.partyId(), order);
                byte[] shared = ecdh(e.privkey(), publicKeyFromRaw65(r.pubkeyRaw65()));
                byte[] info = buildHkdfInfo(r.partyType(), r.partyId());
                byte[] kek = hkdfSha256(shared, saltBytes, info, 32);

                byte[] ctAndTag = aesGcmEncrypt(kek, nonce, aad, currentPlaintext);
                int ctLen = ctAndTag.length - GCM_TAG_BYTES;
                byte[] ciphertext = new byte[ctLen];
                byte[] authTag = new byte[GCM_TAG_BYTES];
                System.arraycopy(ctAndTag, 0, ciphertext, 0, ctLen);
                System.arraycopy(ctAndTag, ctLen, authTag, 0, GCM_TAG_BYTES);

                String layerJson = buildLayerJson(
                        order,
                        r.partyId(),
                        r.partyType(),
                        r.keyFingerprint(),
                        e.pubkeyRaw65(),
                        nonce,
                        ciphertext,
                        authTag);
                currentPlaintext = layerJson.getBytes(StandardCharsets.UTF_8);
            }

            // Step 3: wrap the outermost layer in the envelope.
            // currentPlaintext is now the outermost layer's JSON bytes.
            String outermostLayer = new String(currentPlaintext, StandardCharsets.UTF_8);
            String envelopeJson = buildEnvelopeJson(specVersion, blobId, saltBytes, outermostLayer);
            return Base64.getEncoder().encodeToString(envelopeJson.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("recovery construct failed", ex);
        }
    }

    /** Peel one layer. Inputs:
     *   - encryptedInputB64: envelope (first peel) or prior peeler's output (subsequent peels)
     *   - recipientPrivkey: this peeler's long-lived ECDH-P256 private key
     *   - expectedLayerOrder: 1 on first peel, 2 next, etc.
     *   - expectedPartyType / expectedPartyId: what session state says this peeler must be
     *   - blobId: session metadata (only used to verify envelope on first peel)
     *
     *  On success: returns either innermost lockerKeyHex (last peel) or nextEncrypted bytes. */
    public static PeelResult peel(
            String encryptedInputB64,
            ECPrivateKey recipientPrivkey,
            int expectedLayerOrder,
            String expectedPartyType,
            String expectedPartyId,
            String blobId,
            byte[] envelopeSaltBytes) {  // null on first peel; salt comes from envelope itself
        try {
            byte[] inputBytes = Base64.getDecoder().decode(encryptedInputB64);
            String layerJson;
            byte[] salt;
            if (expectedLayerOrder == 1) {
                // First peel — input is the envelope JSON.
                String envJson = new String(inputBytes, StandardCharsets.UTF_8);
                ParsedEnvelope env = parseEnvelope(envJson);
                if (!"v1".equals(env.specVersion)) {
                    throw new IllegalStateException("Unsupported specVersion: " + env.specVersion);
                }
                if (!blobId.equals(env.blobId)) {
                    throw new IllegalStateException("blobId mismatch: expected " + blobId + " got " + env.blobId);
                }
                layerJson = env.outermostLayerJson;
                salt = hex(env.saltHex);
            } else {
                layerJson = new String(inputBytes, StandardCharsets.UTF_8);
                if (envelopeSaltBytes == null) {
                    throw new IllegalArgumentException("salt must be carried forward after layer 1");
                }
                salt = envelopeSaltBytes;
            }

            ParsedLayer layer = parseLayer(layerJson);
            if (layer.layerOrder != expectedLayerOrder) {
                throw new IllegalStateException("layerOrder mismatch: expected "
                        + expectedLayerOrder + " got " + layer.layerOrder);
            }
            if (!expectedPartyType.equals(layer.partyType)) {
                throw new IllegalStateException("partyType mismatch");
            }
            if (!expectedPartyId.equals(layer.partyId)) {
                throw new IllegalStateException("partyId mismatch");
            }

            byte[] ephRaw65 = Base64.getDecoder().decode(layer.ephPubkeyB64);
            byte[] nonce = Base64.getDecoder().decode(layer.nonceB64);
            byte[] ciphertext = Base64.getDecoder().decode(layer.ciphertextB64);
            byte[] authTag = Base64.getDecoder().decode(layer.authTagB64);

            byte[] aad = buildAad("v1", blobId, layer.partyType, layer.partyId, layer.layerOrder);
            byte[] shared = ecdh(recipientPrivkey, publicKeyFromRaw65(ephRaw65));
            byte[] info = buildHkdfInfo(layer.partyType, layer.partyId);
            byte[] kek = hkdfSha256(shared, salt, info, 32);

            byte[] ctAndTag = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, ctAndTag, 0, ciphertext.length);
            System.arraycopy(authTag, 0, ctAndTag, ciphertext.length, authTag.length);
            byte[] plaintext = aesGcmDecrypt(kek, nonce, aad, ctAndTag);

            // Probe innermost: try to parse as innermost JSON.
            String plaintextStr = new String(plaintext, StandardCharsets.UTF_8);
            if (plaintextStr.contains("\"payloadType\":\"lockerKey\"")) {
                String lockerKeyHex = extractJsonString(plaintextStr, "lockerKeyHex");
                return new PeelResult(true, lockerKeyHex, null);
            }
            return new PeelResult(false, null, plaintext);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("recovery peel failed (AES-GCM tag mismatch?)", ex);
        }
    }

    // ---------- crypto primitives ----------

    public static byte[] ecdh(ECPrivateKey privkey, ECPublicKey pubkey) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privkey);
        ka.doPhase(pubkey, true);
        return ka.generateSecret();
    }

    /** RFC 5869 HKDF-SHA256. */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        // Extract
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        hmac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
        byte[] prk = hmac.doFinal(ikm);
        // Expand
        byte[] result = new byte[length];
        byte[] previousBlock = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < length) {
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            hmac.update(previousBlock);
            hmac.update(info);
            hmac.update((byte) counter);
            previousBlock = hmac.doFinal();
            int copyLen = Math.min(previousBlock.length, length - offset);
            System.arraycopy(previousBlock, 0, result, offset, copyLen);
            offset += copyLen;
            counter++;
        }
        return result;
    }

    /** Returns ciphertext || authTag(16 bytes) concatenated. */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    /** Input must be ciphertext || authTag(16 bytes) concatenated. */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ctAndTag) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ctAndTag);
    }

    public static String sha256Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            return toHex(hash);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    // ---------- AAD + JSON canonical builders ----------

    /** AAD = UTF-8("dt-recovery-v1|<blobId>|<partyType>|<partyId>|<layerOrder>") */
    public static byte[] buildAad(String specVersion, String blobId, String partyType, String partyId, int layerOrder) {
        if (!"v1".equals(specVersion)) {
            throw new IllegalArgumentException("only v1 supported, got " + specVersion);
        }
        String s = "dt-recovery-v1|" + blobId + "|" + partyType + "|" + partyId + "|" + layerOrder;
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** HKDF info = UTF-8("dt-recovery-layer-v1|<partyType>|<partyId>") */
    public static byte[] buildHkdfInfo(String partyType, String partyId) {
        String s = "dt-recovery-layer-v1|" + partyType + "|" + partyId;
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Innermost plaintext JSON, canonical field order:
     *  payloadType, lockerKeyHex, createdAt. No whitespace. */
    public static byte[] buildInnermostJson(byte[] lockerKey, String createdAtIso) {
        if (lockerKey.length != 32) {
            throw new IllegalArgumentException("lockerKey must be 32 bytes");
        }
        String s = "{\"payloadType\":\"lockerKey\","
                + "\"lockerKeyHex\":\"" + toHex(lockerKey) + "\","
                + "\"createdAt\":\"" + createdAtIso + "\"}";
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Layer JSON, canonical field order:
     *  layerOrder, partyId, partyType, keyFingerprint,
     *  ephPubkeyB64, nonceB64, ciphertextB64, authTagB64. No whitespace. */
    public static String buildLayerJson(
            int layerOrder, String partyId, String partyType, String keyFingerprint,
            byte[] ephPubkeyRaw65, byte[] nonce, byte[] ciphertext, byte[] authTag) {
        return "{"
                + "\"layerOrder\":" + layerOrder + ","
                + "\"partyId\":\"" + partyId + "\","
                + "\"partyType\":\"" + partyType + "\","
                + "\"keyFingerprint\":\"" + keyFingerprint + "\","
                + "\"ephPubkeyB64\":\"" + Base64.getEncoder().encodeToString(ephPubkeyRaw65) + "\","
                + "\"nonceB64\":\"" + Base64.getEncoder().encodeToString(nonce) + "\","
                + "\"ciphertextB64\":\"" + Base64.getEncoder().encodeToString(ciphertext) + "\","
                + "\"authTagB64\":\"" + Base64.getEncoder().encodeToString(authTag) + "\""
                + "}";
    }

    /** Envelope JSON, canonical field order: specVersion, blobId, saltHex, layers (array of 1).
     *  No whitespace. */
    public static String buildEnvelopeJson(String specVersion, String blobId, byte[] saltBytes, String outermostLayerJson) {
        return "{"
                + "\"specVersion\":\"" + specVersion + "\","
                + "\"blobId\":\"" + blobId + "\","
                + "\"saltHex\":\"" + toHex(saltBytes) + "\","
                + "\"layers\":[" + outermostLayerJson + "]"
                + "}";
    }

    // ---------- key import helpers ----------

    public static ECPrivateKey privkeyFromPkcs8Hex(String pkcs8Hex) {
        try {
            byte[] der = hex(pkcs8Hex);
            return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("Failed to parse PKCS#8: " + ex.getMessage(), ex);
        }
    }

    public static ECPublicKey publicKeyFromSpkiHex(String spkiHex) {
        try {
            byte[] der = hex(spkiHex);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("Failed to parse SPKI: " + ex.getMessage(), ex);
        }
    }

    /** Convert a 65-byte uncompressed SEC1 P-256 point (0x04 || X || Y) to an ECPublicKey. */
    public static ECPublicKey publicKeyFromRaw65(byte[] raw65) {
        if (raw65 == null || raw65.length != 65 || raw65[0] != 0x04) {
            throw new IllegalArgumentException("Expected 65-byte uncompressed SEC1 point (must start with 0x04)");
        }
        byte[] spki = new byte[P256_SPKI_PREFIX.length + raw65.length];
        System.arraycopy(P256_SPKI_PREFIX, 0, spki, 0, P256_SPKI_PREFIX.length);
        System.arraycopy(raw65, 0, spki, P256_SPKI_PREFIX.length, raw65.length);
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("Failed to wrap raw SEC1 in SPKI: " + ex.getMessage(), ex);
        }
    }

    /** Convert an ECPublicKey to its 65-byte uncompressed SEC1 form (0x04 || X || Y). */
    public static byte[] publicKeyToRaw65(ECPublicKey pubkey) {
        byte[] x = bigIntTo32Bytes(pubkey.getW().getAffineX());
        byte[] y = bigIntTo32Bytes(pubkey.getW().getAffineY());
        byte[] raw = new byte[65];
        raw[0] = 0x04;
        System.arraycopy(x, 0, raw, 1, 32);
        System.arraycopy(y, 0, raw, 33, 32);
        return raw;
    }

    // ---------- minimal JSON parser (only what peel needs) ----------

    private record ParsedEnvelope(String specVersion, String blobId, String saltHex, String outermostLayerJson) {}

    private record ParsedLayer(int layerOrder, String partyId, String partyType, String keyFingerprint,
                                String ephPubkeyB64, String nonceB64, String ciphertextB64, String authTagB64) {}

    private static ParsedEnvelope parseEnvelope(String json) {
        String specVersion = extractJsonString(json, "specVersion");
        String blobId = extractJsonString(json, "blobId");
        String saltHex = extractJsonString(json, "saltHex");
        // The "layers" array contains a single layer object (russian-doll).
        // We extract the object verbatim by matching balanced braces after "layers":[ ... ]
        int start = json.indexOf("\"layers\":[");
        if (start < 0) {
            throw new IllegalArgumentException("envelope missing layers");
        }
        int objStart = json.indexOf('{', start);
        int depth = 0;
        int i = objStart;
        for (; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    break;
                }
            }
        }
        String outermost = json.substring(objStart, i + 1);
        return new ParsedEnvelope(specVersion, blobId, saltHex, outermost);
    }

    private static ParsedLayer parseLayer(String json) {
        int layerOrder = Integer.parseInt(extractJsonNumber(json, "layerOrder"));
        return new ParsedLayer(
                layerOrder,
                extractJsonString(json, "partyId"),
                extractJsonString(json, "partyType"),
                extractJsonString(json, "keyFingerprint"),
                extractJsonString(json, "ephPubkeyB64"),
                extractJsonString(json, "nonceB64"),
                extractJsonString(json, "ciphertextB64"),
                extractJsonString(json, "authTagB64"));
    }

    /** Extract a string value for the named key from a flat JSON object.
     *  Adequate for the controlled JSON shapes this class produces; not a general parser. */
    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            throw new IllegalArgumentException("missing key: " + key);
        }
        start += needle.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    private static String extractJsonNumber(String json, String key) {
        String needle = "\"" + key + "\":";
        int start = json.indexOf(needle);
        if (start < 0) {
            throw new IllegalArgumentException("missing key: " + key);
        }
        start += needle.length();
        int end = start;
        while (end < json.length() && "0123456789-".indexOf(json.charAt(end)) >= 0) {
            end++;
        }
        return json.substring(start, end);
    }

    // ---------- hex / bytes helpers ----------

    public static byte[] hex(String h) {
        if ((h.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length: " + h.length());
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(String.format("%02x", v & 0xFF));
        }
        return sb.toString();
    }

    /** Convert a non-negative BigInteger to a left-zero-padded 32-byte array. */
    public static byte[] bigIntTo32Bytes(BigInteger n) {
        byte[] src = n.toByteArray();
        byte[] dst = new byte[32];
        // src may have a leading 0x00 sign byte (length 33) for positive numbers with high bit set;
        // or may be shorter than 32 bytes.
        int srcOffset = Math.max(0, src.length - 32);
        int dstOffset = Math.max(0, 32 - src.length);
        int copyLen = Math.min(32, src.length);
        System.arraycopy(src, srcOffset, dst, dstOffset, copyLen);
        return dst;
    }

    /** Return ciphertext-only and authTag-only as a record, given the concatenated output of aesGcmEncrypt. */
    public static record CtTag(byte[] ciphertext, byte[] authTag) {
        public static CtTag split(byte[] ctAndTag) {
            int n = ctAndTag.length - GCM_TAG_BYTES;
            byte[] ct = new byte[n];
            byte[] tag = new byte[GCM_TAG_BYTES];
            System.arraycopy(ctAndTag, 0, ct, 0, n);
            System.arraycopy(ctAndTag, n, tag, 0, GCM_TAG_BYTES);
            return new CtTag(ct, tag);
        }
    }

    /** Sugar: build a List of recipients quickly in tests. */
    public static List<Recipient> recipients(Recipient... items) {
        List<Recipient> out = new ArrayList<>();
        for (Recipient r : items) {
            out.add(r);
        }
        return out;
    }
}
