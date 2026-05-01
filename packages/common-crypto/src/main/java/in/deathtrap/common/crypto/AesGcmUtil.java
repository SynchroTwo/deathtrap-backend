package in.deathtrap.common.crypto;

import in.deathtrap.common.errors.AppException;
import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Server-side AES-GCM utility for internal symmetric encryption only. Server never decrypts user key blobs. */
public final class AesGcmUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int GCM_TAG_LENGTH_BITS = 128;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private AesGcmUtil() {}

    /**
     * Encrypts plaintext using AES-256-GCM.
     *
     * @param plaintext the data to encrypt
     * @param key       256-bit AES key
     * @param nonce     96-bit nonce
     * @return ciphertext with auth tag appended
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
            GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException ex) {
            throw AppException.internalError();
        }
    }

    /**
     * Decrypts ciphertext using AES-256-GCM.
     *
     * @param ciphertext ciphertext with auth tag appended
     * @param key        256-bit AES key
     * @param nonce      96-bit nonce
     * @return decrypted plaintext
     * @throws AppException if authentication tag verification fails
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
            GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException ex) {
            throw new AppException(in.deathtrap.common.errors.ErrorCode.INTERNAL_ERROR,
                    "Decryption failed — authentication tag mismatch");
        }
    }
}
