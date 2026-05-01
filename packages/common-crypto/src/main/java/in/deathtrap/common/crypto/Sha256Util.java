package in.deathtrap.common.crypto;

import in.deathtrap.common.errors.AppException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 hashing utilities using the JDK MessageDigest. */
public final class Sha256Util {

    private static final String ALGORITHM = "SHA-256";
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private Sha256Util() {}

    /**
     * Hashes the given string and returns a 64-character hex string.
     *
     * @param input the string to hash
     * @return 64-char lowercase hex digest
     */
    public static String hashHex(String input) {
        return hashHex(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Hashes the given bytes and returns a 64-character hex string.
     *
     * @param input the bytes to hash
     * @return 64-char lowercase hex digest
     */
    public static String hashHex(byte[] input) {
        byte[] digest = hash(input);
        return toHex(digest);
    }

    /**
     * Hashes the given bytes and returns the raw digest bytes.
     *
     * @param input the bytes to hash
     * @return 32-byte SHA-256 digest
     */
    public static byte[] hash(byte[] input) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw AppException.internalError();
        }
    }

    private static String toHex(byte[] bytes) {
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            result[i * 2] = HEX_CHARS[v >>> 4];
            result[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(result);
    }
}
