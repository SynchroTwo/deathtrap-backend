package in.deathtrap.recovery.refimpl;

import in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.Ephemeral;
import in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.PeelResult;
import in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.Recipient;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.hex;
import static in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.privkeyFromPkcs8Hex;
import static in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.publicKeyFromSpkiHex;
import static in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.sha256Hex;
import static in.deathtrap.recovery.refimpl.RecoveryBlobV1Reference.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Byte-equality test of the Java reference implementation against the pinned
 * test vectors in {@code docs/RECOVERY_TEST_VECTORS_V1.md}.
 * <p>
 * If this test passes, the Java construct/peel pipeline matches the UI's TS
 * reference impl byte-for-byte for these inputs — meaning the spec
 * ({@code docs/RECOVERY_BLOB_FORMAT.md}) is implementable consistently across
 * both platforms.
 * <p>
 * If any assertion fails, the failure message names the field that diverged.
 * Common failure modes and what they imply:
 * <ul>
 *   <li>Innermost plaintext mismatch → JSON canonicalization of innermost
 *       differs (check field order / escaping / whitespace).</li>
 *   <li>Layer-3 ciphertext/tag mismatch → ECDH or HKDF outputs differ for
 *       nominee2; check shared secret hex first.</li>
 *   <li>Envelope mismatch with layer-N ciphertexts matching → envelope JSON
 *       canonical form differs (saltHex casing, field order, layers array
 *       handling).</li>
 * </ul>
 */
class RecoveryBlobV1ReferenceTest {

    // ---------- Pinned inputs (§1 of test vectors doc) ----------

    private static final String BLOB_ID = "1e2c3a44-9b10-4d51-bfe2-77c8a2419f01";
    private static final String SALT_HEX =
            "4242424242424242424242424242424242424242424242424242424242424242";
    private static final String LOCKER_KEY_HEX =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    private static final String INNERMOST_CREATED_AT = "2026-01-01T00:00:00.000Z";

    private static final String LAWYER_ID = "8f429100-ec91-4a9d-bc9b-cffd940142c8";
    private static final String LAWYER_PRIVKEY_PKCS8_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "0420a209e6dc13cde58efc78177da7934910ce9a80c29f38994d2dacba208636342c"
          + "a144034200044e1f66c6f36b1ecc0a74c3e9346be0843b57f93ff529ea93f324e75b"
          + "9e1fe4e4ae87c1f499dc66d3d0938458a4c700543c18a915ec9c219cf4e0b5b0d032"
          + "5031";
    private static final String LAWYER_PUBKEY_SPKI_HEX =
            "3059301306072a8648ce3d020106082a8648ce3d030107034200044e1f66c6f36b1e"
          + "cc0a74c3e9346be0843b57f93ff529ea93f324e75b9e1fe4e4ae87c1f499dc66d3d0"
          + "938458a4c700543c18a915ec9c219cf4e0b5b0d0325031";
    private static final String LAWYER_FP =
            "48a350c5399b8ac924ed5c7b8a2cd95abd21a67a77353a14e12eaa4686c84789";

    private static final String NOMINEE1_ID = "c2d0a4f1-1234-4ef2-9876-aaaaaaaaaaaa";
    private static final String NOMINEE1_PRIVKEY_PKCS8_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "0420d64e7b5b3922833ba24f71efd4d76271fa2137da705bf9f9c0a307e3fdb2d092"
          + "a14403420004d8835d254ed03521da6c06d06025e9f250b476994aeca67cfdfcb58e"
          + "3b4244423244e9b68a6dc30f694e3164319838ca311461e5e39d1c7e67063012d78e"
          + "e1c5";
    private static final String NOMINEE1_PUBKEY_SPKI_HEX =
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004d8835d254ed035"
          + "21da6c06d06025e9f250b476994aeca67cfdfcb58e3b4244423244e9b68a6dc30f69"
          + "4e3164319838ca311461e5e39d1c7e67063012d78ee1c5";
    private static final String NOMINEE1_FP =
            "7caeeebb2389d9a6fd679cb726a1adce92bee20010c6db10a72462c82afcfecc";

    private static final String NOMINEE2_ID = "c2d0a4f1-5678-4ef2-9876-bbbbbbbbbbbb";
    private static final String NOMINEE2_PRIVKEY_PKCS8_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "0420f58c83110a29c668398d329d5cb0b45b690334005f0df6196594b921ae86d57a"
          + "a14403420004d543cdec9c1d71396cfa4abf636d95dbfe78e30e3ad1c22edaacfaba"
          + "b16e8af3be2b7c5ef6d17531e4aa699c2426677efd07d97fb4960a13589aaa9482cc"
          + "2274";
    private static final String NOMINEE2_PUBKEY_SPKI_HEX =
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004d543cdec9c1d71"
          + "396cfa4abf636d95dbfe78e30e3ad1c22edaacfabab16e8af3be2b7c5ef6d17531e4"
          + "aa699c2426677efd07d97fb4960a13589aaa9482cc2274";
    private static final String NOMINEE2_FP =
            "46ecb2584b42112e1181963e434a0be4aa35a41213b0caae6fda7d3efaf6ea5e";

    // ---------- Pinned ephemerals (§2 of test vectors doc) ----------

    private static final String EPH_LAWYER_PRIV_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "04207308cde7caf5c547c409fe4957c4000a49b6782c6b0c5c49e1ff502b4fe446b4"
          + "a144034200043af7084a71e5720f80019f593c8e2f872df1756ea741f55f08cd4f20"
          + "901c136cfaa7fa5195fbf4f83406bb147dc9972390fb14e4571d6d23ae9047915a4e"
          + "56a2";
    private static final String EPH_LAWYER_PUB_RAW65_HEX =
            "043af7084a71e5720f80019f593c8e2f872df1756ea741f55f08cd4f20901c136c"
          + "faa7fa5195fbf4f83406bb147dc9972390fb14e4571d6d23ae9047915a4e56a2";

    private static final String EPH_NOMINEE1_PRIV_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "042092270a7d4f0ec93bd2c04c3f61a5639b9bb0d8d6c91c034eef338b2db45d5699"
          + "a14403420004eb0583f1a8b792573e3db8360bb62e3fc29aec47d55584befacff0aa"
          + "52cec4cf9c2274065baf4274aa9a5c03abd06d219738e3754e0aea05377d748dee1b"
          + "70b4";
    private static final String EPH_NOMINEE1_PUB_RAW65_HEX =
            "04eb0583f1a8b792573e3db8360bb62e3fc29aec47d55584befacff0aa52cec4cf"
          + "9c2274065baf4274aa9a5c03abd06d219738e3754e0aea05377d748dee1b70b4";

    private static final String EPH_NOMINEE2_PRIV_HEX =
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101"
          + "0420b5a5f9bb4194d87b93c96897fdfd5268d4952d5606241f72104c867880d1f82f"
          + "a14403420004bf304d08c72e6b51c1ab6f2451fe5fb73bab5bc7bf51d26f38823e76"
          + "6d7dc3642d3df615834ea68b2ad34e9ff33849130b36c1b190dc7cae0e1e84afece2"
          + "cea8";
    private static final String EPH_NOMINEE2_PUB_RAW65_HEX =
            "04bf304d08c72e6b51c1ab6f2451fe5fb73bab5bc7bf51d26f38823e766d7dc364"
          + "2d3df615834ea68b2ad34e9ff33849130b36c1b190dc7cae0e1e84afece2cea8";

    // ---------- Nonces (§2 of test vectors doc) ----------

    private static final String NONCE_LAYER1_HEX = "111111111111111111111111";
    private static final String NONCE_LAYER2_HEX = "222222222222222222222222";
    private static final String NONCE_LAYER3_HEX = "333333333333333333333333";

    // ---------- Expected outputs from §§3-6 ----------

    // Layer 3 (innermost — nominee2)
    private static final String EXPECTED_L3_SHARED_HEX =
            "a9a55e0bfdbbb80ae7ee1ba2b5f38cf3881a98e95d76bd25db68703222f7f8e0";
    private static final String EXPECTED_L3_KEK_HEX =
            "22e235a875b1f5af35e200ba85b874590f2ce165fec22ad00b45faff84ec0b6b";
    private static final String EXPECTED_L3_CT_HEX =
            "26e792878ed7e21f810b2dfbcc20db78c6e0acad739bc86c29534ee96e5a611287cb"
          + "989eeabbf33381eabee94f13fc9c1eb3128fe5f0acef812f97468eaaa66e549a3fdc"
          + "e787c97d689045448404bcb9d0c830c714cbd8dd80becaf1e85f62de6777d80d443f"
          + "357da45590df341f78b7ec3611e160469215047964b7ebd7a5c852b87d92c2e281ec"
          + "694ebfb5271d146eb9555e92";
    private static final String EXPECTED_L3_TAG_HEX =
            "4ee5a06be074d87db6bb9e1bcc03d1f2";

    // Layer 2 (nominee1)
    private static final String EXPECTED_L2_SHARED_HEX =
            "14ca5cac071005906877bfd0fcaa562963e2bc6137d455a751e24453d5ccb745";
    private static final String EXPECTED_L2_KEK_HEX =
            "c9d7393f7c247daca0994679704297b65be5da68c06cd3a1e3dfa2a8418493e1";

    // Layer 1 (lawyer — outermost)
    private static final String EXPECTED_L1_SHARED_HEX =
            "1bf5d088ac0c5ba39572f141ddd2734e0b14576ce16e4ebfe121edd8d1725860";
    private static final String EXPECTED_L1_KEK_HEX =
            "2a5a8293358a773c39c3081503023c9c87bb5e55ebfd34a45dc5f27d64260d89";

    // Final envelope (§5) — base64-encoded full envelope JSON.
    private static final String EXPECTED_ENCRYPTED_BLOB_B64 =
            "eyJzcGVjVmVyc2lvbiI6InYxIiwiYmxvYklkIjoiMWUyYzNhNDQtOWIxMC00ZDUxLWJm"
          + "ZTItNzdjOGEyNDE5ZjAxIiwic2FsdEhleCI6IjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0"
          + "MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyNDI0MjQyIiwibGF5ZXJzIjpb"
          + "eyJsYXllck9yZGVyIjoxLCJwYXJ0eUlkIjoiOGY0MjkxMDAtZWM5MS00YTlkLWJjOWIt"
          + "Y2ZmZDk0MDE0MmM4IiwicGFydHlUeXBlIjoibGF3eWVyIiwia2V5RmluZ2VycHJpbnQi"
          + "OiI0OGEzNTBjNTM5OWI4YWM5MjRlZDVjN2I4YTJjZDk1YWJkMjFhNjdhNzczNTNhMTRl"
          + "MTJlYWE0Njg2Yzg0Nzg5IiwiZXBoUHVia2V5QjY0IjoiQkRyM0NFcHg1WElQZ0FHZldU"
          + "eU9MNGN0OFhWdXAwSDFYd2pOVHlDUUhCTnMrcWY2VVpYNzlQZzBCcnNVZmNtWEk1RDdG"
          + "T1JYSFcwanJwQkhrVnBPVnFJPSIsIm5vbmNlQjY0IjoiRVJFUkVSRVJFUkVSRVJFUiIs"
          + "ImNpcGhlcnRleHRCNjQiOiJzRXU3VWxsSWg5ZXlzakk1N0RYMTR1NmhDeXB0b09abWFF"
          + "RHczL3RGcW5id0E5czc4UWtEL2N0RGJPaVVZNGp6ZWQ4MEhQb2hUbUFFSU5MREFMTFdE"
          + "c2ZBbTdNakUzSkxNWFhoWEhsdXg3L29TclJaOTg2ZzNxMnZyR0hPYk1TOGdMVVBUZ1Vn"
          + "VGtvMlNnaTdhbXV4ZDRKZjRFMndUVFMzemY0L3ZMWFRTcjZ3WndtazF3RXEzQk1KYWNm"
          + "ZENNWWNyNzBwamEyMzdydThRaldsdDVjRDhNZVlWMjgzRUIydnN6VFVEUHBISDl6c2dJ"
          + "cDIydXVwOGVTSzJMd3FnU0NSWkdBV3JDMnRhcU5UVDhyS2E1ckVHQkhlYjVYVEhjclMw"
          + "L3hGUCtMd0lKdWhWVHNwR3N3UHl6L09CaVY2NFNyMjAvdk9aVVlSVHcyL1FzeW8zYy9P"
          + "RGxnSlpHaFVWOHhwTXRQNkZ3L2NDVXpTUUtLc2J0Wmw0eWk3V0FIY1dzTjBmVlVuWTc3"
          + "Vm5Wa0FScVZSTmJ2b2JZRHBmcU5NT2oybnhYK3FnSDU1NkdFRnZoNzFkeVY5R3BIU1pP"
          + "QXcxZHJ6RmtpSmViU3BvTXRNK1d0R1hLT1RudmFRVW5kdnhqOEk2Sy9tWlZINjZNeDNL"
          + "Z0ZRaTV1UzRUaWU2ODAxbzFheEpSWU9qamNnTXlUNjEvd3FOR3RLakk1WkdJaEl4M1Bk"
          + "NjdjQmI3dXBhdHRjbEhldU9VbTRuMFlxdWw3TzNQTE84cHBETkxHbDhiVWFHWC95bGlJ"
          + "NStRRzNRWmN3SitvdGRwMVRVWm0zUnN5MS84M0JvaU5rT0p4K3Y0NkU4YlRocTl2bURi"
          + "ZzBLMVdaZGRzQU9ld0NObElXUmZLSUg0a1d4TkZIQ3dwTlhBc1d1TVhya1gxY0lyb1Zy"
          + "a0I5bGhiWG5naTczalpRQmJXa3BIakkzYzZ6TmV0TnE4SncvNmRNUzZhbHRDeVgweTk3"
          + "MVRtZmlRczgwOHhxeWFpR1ZTTE9OZXRhdHhUOWpjbW8vaS9lRDFDeUVWUW9qWC9YL1dq"
          + "bjJEd0NxTlU5a1RrN3VPS1pBdDZwM2dpWXg0MTNuaXRob2RQQkkwblFuSlpGKzF6WHYx"
          + "cGYrWW9HUnB5bG02QzZJckJwOGk1MU5qaVZoOGMxbUFkbmlZUlRacDd1Y3pTNVVoWExj"
          + "TGxKRVFpd2MybGtTbDVPZ21QZnN3M3laK0cwcUtJSHpDK0pDdEpQRm1jeVUwT2hIbDF2"
          + "SkVwK1NVdTZxaklJM2tTTlpZYkxUZm9PaEVwbDRwYSthbE1JT3QyMGZMWktraWx6MWg1"
          + "eFROZi9rQkxUSnV6N0NHRDd2MzVNNFBWR1M4UmtUVnhYRW9kWlMyMTBjQlorZDFNM3hE"
          + "bDl5OHVYQy84S0JiNEtpQXBxWVJXMFN3ek4wMUJabmhvOEI3d3RqNTZKcDZqeHpKTklN"
          + "Q0g1emIvV2RmZE9OUXBYSlZzYUphVHd2aTJJRm9ySGYvWVRFcFRJN2haaXF2dTgzK1BN"
          + "alRDSVNaSnRESnV5blJWYk5DT3RGaU5PbDR4eHRPSW0venJvWHRQbHdhWW5RSGpLLy9w"
          + "VXNJa01jdkVtb1ltbTRGdUpGWVFjVHVLRDZVcVBIVFp6YTF4VUd2dTRGeFBYbm5jcU1u"
          + "TUwzZStEYzdRV2tBQVVtQ2NxSjc0SEZJNXZEY3I3VGQ2a0wycWZ0VUk3azhDOGhWSTl3"
          + "NmlQbXdWZ0szSDlkTTE3NmVXcTdSVUtzd1Q4MDRmN3NKZVB1Q293d09VNWhpYkNkT2Vs"
          + "STVLYzNodGxIQVZBMGxoSXZpTkpKQTlnWmthY1VLVnNKbHl1SzdFc0h2WjBZYmNTc2hH"
          + "WTVLY3QvOG00b3p5MThreURwRi9pcG5TSHN2MmxLbnU4Nmg5Q3VJdXl2Yzd0Ykk1Znlz"
          + "Yk5oQzJGU3YxaHFraHBqUjRCRU0zWkxhU1VSa2xUNkJyTiIsImF1dGhUYWdCNjQiOiJD"
          + "clRpOXEvV05jRVdxM2t3NVNZSmNBPT0ifV19";

    @Test
    void buildsEnvelopeAndRoundTripsBytePerByte() throws Exception {
        // --- Step 1: load all pinned long-lived keys ---
        ECPrivateKey lawyerPriv = privkeyFromPkcs8Hex(LAWYER_PRIVKEY_PKCS8_HEX);
        ECPrivateKey nominee1Priv = privkeyFromPkcs8Hex(NOMINEE1_PRIVKEY_PKCS8_HEX);
        ECPrivateKey nominee2Priv = privkeyFromPkcs8Hex(NOMINEE2_PRIVKEY_PKCS8_HEX);

        // Fingerprint sanity (vectors must match SHA-256 of the SPKI DER hex blob).
        assertEquals(LAWYER_FP,    sha256Hex(hex(LAWYER_PUBKEY_SPKI_HEX)),    "lawyer fingerprint");
        assertEquals(NOMINEE1_FP,  sha256Hex(hex(NOMINEE1_PUBKEY_SPKI_HEX)),  "nominee1 fingerprint");
        assertEquals(NOMINEE2_FP,  sha256Hex(hex(NOMINEE2_PUBKEY_SPKI_HEX)),  "nominee2 fingerprint");

        // --- Step 2: build recipients (outermost first: lawyer @ 1, nominee1 @ 2, nominee2 @ 3) ---
        // Wait — the vectors list lawyer first, but the SPKI hex above is a raw SPKI for each;
        // we need each recipient's raw 65-byte SEC1. Extract it from the SPKI DER tail (drop 26-byte prefix).
        Recipient lawyerR = new Recipient(LAWYER_ID, "lawyer",
                spkiTailToRaw65(hex(LAWYER_PUBKEY_SPKI_HEX)), LAWYER_FP);
        Recipient nominee1R = new Recipient(NOMINEE1_ID, "nominee",
                spkiTailToRaw65(hex(NOMINEE1_PUBKEY_SPKI_HEX)), NOMINEE1_FP);
        Recipient nominee2R = new Recipient(NOMINEE2_ID, "nominee",
                spkiTailToRaw65(hex(NOMINEE2_PUBKEY_SPKI_HEX)), NOMINEE2_FP);

        // --- Step 3: ephemerals (one per layerOrder, 1-indexed) ---
        Ephemeral eph1 = new Ephemeral(
                privkeyFromPkcs8Hex(EPH_LAWYER_PRIV_HEX),
                hex(EPH_LAWYER_PUB_RAW65_HEX));
        Ephemeral eph2 = new Ephemeral(
                privkeyFromPkcs8Hex(EPH_NOMINEE1_PRIV_HEX),
                hex(EPH_NOMINEE1_PUB_RAW65_HEX));
        Ephemeral eph3 = new Ephemeral(
                privkeyFromPkcs8Hex(EPH_NOMINEE2_PRIV_HEX),
                hex(EPH_NOMINEE2_PUB_RAW65_HEX));

        // --- Step 4: spot-check per-layer ECDH + KEK using innermost (layer 3) intermediates ---
        // This is the cheapest divergence check: if ECDH or HKDF differ here, no point continuing.
        byte[] shared3 = RecoveryBlobV1Reference.ecdh(
                eph3.privkey(),
                RecoveryBlobV1Reference.publicKeyFromRaw65(nominee2R.pubkeyRaw65()));
        assertEquals(EXPECTED_L3_SHARED_HEX, toHex(shared3), "Layer 3 ECDH shared secret");

        byte[] info3 = RecoveryBlobV1Reference.buildHkdfInfo("nominee", NOMINEE2_ID);
        byte[] kek3 = RecoveryBlobV1Reference.hkdfSha256(shared3, hex(SALT_HEX), info3, 32);
        assertEquals(EXPECTED_L3_KEK_HEX, toHex(kek3), "Layer 3 HKDF KEK");

        // Spot-check layer 2 and layer 1 KEKs too, for diagnostic value.
        byte[] shared2 = RecoveryBlobV1Reference.ecdh(
                eph2.privkey(),
                RecoveryBlobV1Reference.publicKeyFromRaw65(nominee1R.pubkeyRaw65()));
        assertEquals(EXPECTED_L2_SHARED_HEX, toHex(shared2), "Layer 2 ECDH shared secret");
        byte[] kek2 = RecoveryBlobV1Reference.hkdfSha256(shared2, hex(SALT_HEX),
                RecoveryBlobV1Reference.buildHkdfInfo("nominee", NOMINEE1_ID), 32);
        assertEquals(EXPECTED_L2_KEK_HEX, toHex(kek2), "Layer 2 HKDF KEK");

        byte[] shared1 = RecoveryBlobV1Reference.ecdh(
                eph1.privkey(),
                RecoveryBlobV1Reference.publicKeyFromRaw65(lawyerR.pubkeyRaw65()));
        assertEquals(EXPECTED_L1_SHARED_HEX, toHex(shared1), "Layer 1 ECDH shared secret");
        byte[] kek1 = RecoveryBlobV1Reference.hkdfSha256(shared1, hex(SALT_HEX),
                RecoveryBlobV1Reference.buildHkdfInfo("lawyer", LAWYER_ID), 32);
        assertEquals(EXPECTED_L1_KEK_HEX, toHex(kek1), "Layer 1 HKDF KEK");

        // --- Step 5: full construct, assert envelope byte-equality (§5) ---
        String encryptedBlobB64 = RecoveryBlobV1Reference.construct(
                "v1",
                BLOB_ID,
                hex(SALT_HEX),
                hex(LOCKER_KEY_HEX),
                INNERMOST_CREATED_AT,
                List.of(lawyerR, nominee1R, nominee2R),
                List.of(eph1, eph2, eph3),
                List.of(hex(NONCE_LAYER1_HEX), hex(NONCE_LAYER2_HEX), hex(NONCE_LAYER3_HEX)));

        assertEquals(EXPECTED_ENCRYPTED_BLOB_B64, encryptedBlobB64,
                "encryptedBlobB64 must be byte-identical to docs/RECOVERY_TEST_VECTORS_V1.md §5");

        // --- Step 6: peel walkthrough (§6) ---
        // Step 6.1: lawyer peels layer 1.
        PeelResult peel1 = RecoveryBlobV1Reference.peel(
                encryptedBlobB64, lawyerPriv, 1, "lawyer", LAWYER_ID, BLOB_ID, null);
        assertTrue(!peel1.isInnermost(), "Peel 1 must NOT be innermost (lawyer is outermost)");

        // Step 6.2: nominee1 peels layer 2. Input is the bytes of layer-2 JSON.
        String layer2InputB64 = Base64.getEncoder().encodeToString(peel1.nextEncrypted());
        PeelResult peel2 = RecoveryBlobV1Reference.peel(
                layer2InputB64, nominee1Priv, 2, "nominee", NOMINEE1_ID, BLOB_ID,
                hex(SALT_HEX));
        assertTrue(!peel2.isInnermost(), "Peel 2 must NOT be innermost");

        // Step 6.3: nominee2 peels layer 3 (innermost). Reveals lockerKey.
        String layer3InputB64 = Base64.getEncoder().encodeToString(peel2.nextEncrypted());
        PeelResult peel3 = RecoveryBlobV1Reference.peel(
                layer3InputB64, nominee2Priv, 3, "nominee", NOMINEE2_ID, BLOB_ID,
                hex(SALT_HEX));
        assertTrue(peel3.isInnermost(), "Peel 3 must be innermost (the innermost layer)");
        assertEquals(LOCKER_KEY_HEX, peel3.lockerKeyHex(),
                "Recovered lockerKey hex must equal the pinned input — round trip complete");
    }

    /** Strip the 26-byte P-256 SPKI prefix to yield the 65-byte raw uncompressed SEC1 point. */
    private static byte[] spkiTailToRaw65(byte[] spki) {
        if (spki.length != 91) {
            throw new IllegalArgumentException("Expected 91-byte P-256 SPKI, got " + spki.length);
        }
        byte[] raw65 = new byte[65];
        System.arraycopy(spki, 26, raw65, 0, 65);
        if (raw65[0] != 0x04) {
            throw new IllegalArgumentException("SPKI did not contain uncompressed point");
        }
        return raw65;
    }
}
