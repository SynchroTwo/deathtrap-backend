package in.deathtrap.auth.routes.passphrase;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Stub handler for passphrase change — Sprint 2. */
@RestController
@RequestMapping("/auth/passphrase")
public class ChangePassphraseHandler {

    /** POST /auth/passphrase/change — not yet implemented. */
    @PostMapping("/change")
    public ResponseEntity<ApiResponse<Map<String, String>>> changePassphrase() {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(Map.of("status", "not_implemented"), requestId));
    }
}
