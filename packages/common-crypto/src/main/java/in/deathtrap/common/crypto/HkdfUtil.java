package in.deathtrap.common.crypto;

import in.deathtrap.common.errors.AppException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 5869 HKDF implementation using HMAC-SHA-256. */
public final class HkdfUtil {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private HkdfUtil() {}

    /**
     * HKDF Extract step — derives a pseudorandom key from input key material.
     *
     * @param ikm  input key material
     * @param salt optional salt (use zeros if null)
     * @return pseudorandom key (PRK)
     */
    public static byte[] extract(byte[] ikm, byte[] salt) {
        try {
            byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(actualSalt, HMAC_SHA256));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException ex) {
            throw AppException.internalError();
        }
    }

    /**
     * HKDF Expand step — expands a PRK to the desired output length.
     *
     * @param prk         pseudorandom key from extract step
     * @param info        context and application-specific information
     * @param lengthBytes desired output length in bytes
     * @return derived key material
     */
    public static byte[] expand(byte[] prk, byte[] info, int lengthBytes) {
        try {
            int n = (int) Math.ceil((double) lengthBytes / HASH_LEN);
            byte[] okm = new byte[n * HASH_LEN];
            byte[] t = new byte[0];
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(prk, HMAC_SHA256));
            for (int i = 1; i <= n; i++) {
                mac.update(t);
                if (info != null) { mac.update(info); }
                mac.update((byte) i);
                t = mac.doFinal();
                System.arraycopy(t, 0, okm, (i - 1) * HASH_LEN, HASH_LEN);
            }
            return Arrays.copyOf(okm, lengthBytes);
        } catch (GeneralSecurityException ex) {
            throw AppException.internalError();
        }
    }

    /**
     * Convenience method combining extract and expand into a single call.
     *
     * @param ikm         input key material
     * @param salt        optional salt
     * @param info        context info
     * @param lengthBytes desired output length in bytes
     * @return derived key material
     */
    public static byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info, int lengthBytes) {
        byte[] prk = extract(ikm, salt);
        return expand(prk, info, lengthBytes);
    }
}
