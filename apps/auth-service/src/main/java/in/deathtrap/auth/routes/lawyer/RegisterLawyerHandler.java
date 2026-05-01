package in.deathtrap.auth.routes.lawyer;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Stub handler for lawyer registration — Sprint 2. */
@RestController
@RequestMapping("/auth/lawyer")
public class RegisterLawyerHandler {

    /** POST /auth/lawyer/register — not yet implemented. */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, String>>> registerLawyer() {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(Map.of("status", "not_implemented"), requestId));
    }
}
