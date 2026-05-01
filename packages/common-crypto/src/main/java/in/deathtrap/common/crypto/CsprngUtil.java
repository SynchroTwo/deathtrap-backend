package in.deathtrap.common.crypto;

import java.security.SecureRandom;

/** Cryptographically secure random value generators. */
public final class CsprngUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    // Crockford base32 alphabet (no I, L, O, U to avoid visual confusion)
    private static final char[] CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();

    private CsprngUtil() {}

    /**
     * Generates cryptographically random bytes.
     *
     * @param length number of bytes to generate
     * @return random byte array
     */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates cryptographically random bytes encoded as a hex string.
     *
     * @param byteLength number of random bytes (hex string length = byteLength * 2)
     * @return lowercase hex string
     */
    public static String randomHex(int byteLength) {
        byte[] bytes = randomBytes(byteLength);
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX_CHARS[v >>> 4];
            hex[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hex);
    }

    /**
     * Generates a ULID (Universally Unique Lexicographically Sortable Identifier).
     * Format: 26 Crockford base32 characters — 10 chars timestamp + 16 chars randomness.
     *
     * @return 26-character ULID string
     */
    public static String randomUlid() {
        long timestampMs = System.currentTimeMillis();
        byte[] randomPart = randomBytes(10);

        char[] ulid = new char[26];

        // Encode 48-bit timestamp into first 10 characters
        ulid[0] = CROCKFORD_BASE32[(int) ((timestampMs >>> 45) & 0x1F)];
        ulid[1] = CROCKFORD_BASE32[(int) ((timestampMs >>> 40) & 0x1F)];
        ulid[2] = CROCKFORD_BASE32[(int) ((timestampMs >>> 35) & 0x1F)];
        ulid[3] = CROCKFORD_BASE32[(int) ((timestampMs >>> 30) & 0x1F)];
        ulid[4] = CROCKFORD_BASE32[(int) ((timestampMs >>> 25) & 0x1F)];
        ulid[5] = CROCKFORD_BASE32[(int) ((timestampMs >>> 20) & 0x1F)];
        ulid[6] = CROCKFORD_BASE32[(int) ((timestampMs >>> 15) & 0x1F)];
        ulid[7] = CROCKFORD_BASE32[(int) ((timestampMs >>> 10) & 0x1F)];
        ulid[8] = CROCKFORD_BASE32[(int) ((timestampMs >>> 5) & 0x1F)];
        ulid[9] = CROCKFORD_BASE32[(int) (timestampMs & 0x1F)];

        // Encode 80 bits of randomness into last 16 characters
        long r0 = ((long) (randomPart[0] & 0xFF) << 32)
                | ((long) (randomPart[1] & 0xFF) << 24)
                | ((randomPart[2] & 0xFF) << 16)
                | ((randomPart[3] & 0xFF) << 8)
                | (randomPart[4] & 0xFF);
        long r1 = ((long) (randomPart[5] & 0xFF) << 32)
                | ((long) (randomPart[6] & 0xFF) << 24)
                | ((randomPart[7] & 0xFF) << 16)
                | ((randomPart[8] & 0xFF) << 8)
                | (randomPart[9] & 0xFF);

        ulid[10] = CROCKFORD_BASE32[(int) ((r0 >>> 35) & 0x1F)];
        ulid[11] = CROCKFORD_BASE32[(int) ((r0 >>> 30) & 0x1F)];
        ulid[12] = CROCKFORD_BASE32[(int) ((r0 >>> 25) & 0x1F)];
        ulid[13] = CROCKFORD_BASE32[(int) ((r0 >>> 20) & 0x1F)];
        ulid[14] = CROCKFORD_BASE32[(int) ((r0 >>> 15) & 0x1F)];
        ulid[15] = CROCKFORD_BASE32[(int) ((r0 >>> 10) & 0x1F)];
        ulid[16] = CROCKFORD_BASE32[(int) ((r0 >>> 5) & 0x1F)];
        ulid[17] = CROCKFORD_BASE32[(int) (r0 & 0x1F)];
        ulid[18] = CROCKFORD_BASE32[(int) ((r1 >>> 35) & 0x1F)];
        ulid[19] = CROCKFORD_BASE32[(int) ((r1 >>> 30) & 0x1F)];
        ulid[20] = CROCKFORD_BASE32[(int) ((r1 >>> 25) & 0x1F)];
        ulid[21] = CROCKFORD_BASE32[(int) ((r1 >>> 20) & 0x1F)];
        ulid[22] = CROCKFORD_BASE32[(int) ((r1 >>> 15) & 0x1F)];
        ulid[23] = CROCKFORD_BASE32[(int) ((r1 >>> 10) & 0x1F)];
        ulid[24] = CROCKFORD_BASE32[(int) ((r1 >>> 5) & 0x1F)];
        ulid[25] = CROCKFORD_BASE32[(int) (r1 & 0x1F)];

        return new String(ulid);
    }
}
