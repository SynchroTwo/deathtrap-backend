package in.deathtrap.common.crypto;

import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/** Unit tests for HibpClient — no network calls. */
@ExtendWith(MockitoExtension.class)
class HibpClientTest {

    @Spy
    private HibpClient hibpClient;

    @Mock
    private HttpURLConnection mockConn;

    private static final String PREFIX = "ABCDE";
    private static final String SUFFIX = "C".repeat(35);

    private ByteArrayInputStream hibpResponse(String... lines) {
        return new ByteArrayInputStream(
                String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void passphraseNotInDatabase_noException() throws IOException {
        doReturn(mockConn).when(hibpClient).createConnection(anyString());
        when(mockConn.getResponseCode()).thenReturn(200);
        when(mockConn.getInputStream()).thenReturn(hibpResponse("D".repeat(35) + ":5"));

        assertDoesNotThrow(() -> hibpClient.checkPassphrase(PREFIX, SUFFIX, true));
    }

    @Test
    void passphraseFoundInDatabase_throwsCompromised() throws IOException {
        doReturn(mockConn).when(hibpClient).createConnection(anyString());
        when(mockConn.getResponseCode()).thenReturn(200);
        when(mockConn.getInputStream()).thenReturn(hibpResponse(SUFFIX + ":42"));

        AppException ex = assertThrows(AppException.class,
                () -> hibpClient.checkPassphrase(PREFIX, SUFFIX, true));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void apiReturnsNon200_clientFlagFalse_throwsCompromised() throws IOException {
        doReturn(mockConn).when(hibpClient).createConnection(anyString());
        when(mockConn.getResponseCode()).thenReturn(503);

        AppException ex = assertThrows(AppException.class,
                () -> hibpClient.checkPassphrase(PREFIX, SUFFIX, false));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void apiReturnsNon200_clientFlagTrue_noException() throws IOException {
        doReturn(mockConn).when(hibpClient).createConnection(anyString());
        when(mockConn.getResponseCode()).thenReturn(503);

        assertDoesNotThrow(() -> hibpClient.checkPassphrase(PREFIX, SUFFIX, true));
    }

    @Test
    void networkError_clientFlagFalse_throwsCompromised() throws IOException {
        doThrow(new IOException("Network error"))
                .when(hibpClient).createConnection(anyString());

        AppException ex = assertThrows(AppException.class,
                () -> hibpClient.checkPassphrase(PREFIX, SUFFIX, false));

        assertEquals(ErrorCode.AUTH_PASSPHRASE_COMPROMISED, ex.getErrorCode());
    }

    @Test
    void networkError_clientFlagTrue_noException() throws IOException {
        doThrow(new IOException("Network error"))
                .when(hibpClient).createConnection(anyString());

        assertDoesNotThrow(() -> hibpClient.checkPassphrase(PREFIX, SUFFIX, true));
    }

    @Test
    void nullPrefix_throwsValidationFailed() {
        AppException ex = assertThrows(AppException.class,
                () -> hibpClient.checkPassphrase(null, SUFFIX, true));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }

    @Test
    void nullSuffix_throwsValidationFailed() {
        AppException ex = assertThrows(AppException.class,
                () -> hibpClient.checkPassphrase(PREFIX, null, true));

        assertEquals(ErrorCode.VALIDATION_FAILED, ex.getErrorCode());
    }
}
