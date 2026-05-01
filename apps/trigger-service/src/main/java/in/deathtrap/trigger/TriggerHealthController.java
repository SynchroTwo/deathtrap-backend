package in.deathtrap.trigger;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Health check endpoint for the trigger service. */
@RestController
@RequestMapping("/trigger")
public class TriggerHealthController {
    /** GET /trigger/health — returns service status. */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, String>>> health() {
        return ResponseEntity.ok(ApiResponse.ok(
                Map.of("service", "trigger-service", "status", "ok"),
                UUID.randomUUID().toString()));
    }
}
