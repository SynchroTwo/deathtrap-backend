package in.deathtrap.recovery.routes.config;

import in.deathtrap.common.types.api.ApiResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecoveryConfigHandlerTest {

    private final RecoveryConfigHandler handler = new RecoveryConfigHandler();

    @Test
    void returnsV1OnlyDefaults() {
        ResponseEntity<ApiResponse<Object>> response =
                (ResponseEntity<ApiResponse<Object>>) (ResponseEntity<?>) handler.config();

        assertEquals(200, response.getStatusCode().value());
        Object data = response.getBody().data();
        assertNotNull(data);
        // Read fields via the record's toString — keeps the test free of the private record type.
        String repr = data.toString();
        assertTrue(repr.contains("minWriteSpecVersion=v1"), repr);
        assertTrue(repr.contains("currentRecommendedSpecVersion=v1"), repr);
        assertTrue(repr.contains("supportedSpecVersionsForRead=[v1]"), repr);
    }
}
