package in.deathtrap.common.crypto;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Checks passphrases against the HaveIBeenPwned k-anonymity API.
 * The server never receives the full passphrase — only a 5-char SHA-1 prefix.
 */
@Component
public class HibpClient {

    private static final Logger log = LoggerFactory.getLogger(HibpClient.class);
    private static final String HIBP_API = "https://api.pwnedpasswords.com/range/";
    private static final int TIMEOUT_MS = 3000;
    private static final int PREFIX_LENGTH = 5;
    private static final int SUFFIX_LENGTH = 35;

    /**
     * Checks if the passphrase appears in known data breaches using k-anonymity.
     * @param hibpPrefix first 5 hex chars of SHA-1(passphrase)
     * @param hibpSuffix remaining 35 hex chars of SHA-1(passphrase)
     * @param clientFlag client-side check result (used as fallback if API unavailable)
     * @throws AppException if passphrase is breached or inputs are invalid
     */
    public void checkPassphrase(String hibpPrefix, String hibpSuffix, boolean clientFlag) {
        if (hibpPrefix == null || hibpPrefix.length() != PREFIX_LENGTH) {
            throw new AppException(ErrorCode.VALIDATION_FAILED);
        }
        if (hibpSuffix == null || hibpSuffix.length() != SUFFIX_LENGTH) {
            throw new AppException(ErrorCode.VALIDATION_FAILED);
        }

        try {
            HttpURLConnection conn = createConnection(HIBP_API + hibpPrefix.toUpperCase());
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "DeathTrap/1.0");
            conn.setRequestProperty("Add-Padding", "true");

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                log.warn("HIBP API returned non-200: {} — trusting client flag={}", responseCode, clientFlag);
                checkClientFlag(clientFlag);
                return;
            }

            String suffixUpper = hibpSuffix.toUpperCase();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length >= 1 && parts[0].trim().equalsIgnoreCase(suffixUpper)) {
                        throw AppException.passphraseCompromised();
                    }
                }
            }
        } catch (AppException e) {
            throw e;
        } catch (Exception e) {
            log.warn("HIBP API call failed: {} — trusting client flag={}", e.getMessage(), clientFlag);
            checkClientFlag(clientFlag);
        }
    }

    /** Opens an HTTP connection to the given URL. Overridable in tests. */
    protected HttpURLConnection createConnection(String urlString) throws IOException {
        return (HttpURLConnection) new URL(urlString).openConnection();
    }

    private void checkClientFlag(boolean clientFlag) {
        if (!clientFlag) {
            throw AppException.passphraseCompromised();
        }
    }
}
