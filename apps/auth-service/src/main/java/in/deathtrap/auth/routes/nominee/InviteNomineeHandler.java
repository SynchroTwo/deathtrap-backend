package in.deathtrap.auth.routes.nominee;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Stub handler for nominee invitation — Sprint 2. */
@RestController
@RequestMapping("/auth/nominee")
public class InviteNomineeHandler {

    /** POST /auth/nominee/invite — not yet implemented. */
    @PostMapping("/invite")
    public ResponseEntity<ApiResponse<Map<String, String>>> inviteNominee() {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(Map.of("status", "not_implemented"), requestId));
    }
}
