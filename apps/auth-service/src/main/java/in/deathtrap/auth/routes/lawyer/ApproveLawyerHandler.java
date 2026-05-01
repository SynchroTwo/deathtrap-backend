package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Stub handler for lawyer approval — Sprint 2. */
@RestController
@RequestMapping("/auth/lawyer")
public class ApproveLawyerHandler {

    /** POST /auth/lawyer/approve — not yet implemented. */
    @PostMapping("/approve")
    public ResponseEntity<ApiResponse<Map<String, String>>> approveLawyer() {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(Map.of("status", "not_implemented"), requestId));
    }
}
