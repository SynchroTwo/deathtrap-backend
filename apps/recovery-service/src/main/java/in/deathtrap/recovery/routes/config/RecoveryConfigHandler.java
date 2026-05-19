package in.deathtrap.recovery.routes.config;

import in.deathtrap.common.types.api.ApiResponse;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** GET /recovery/config — refuse-to-act gate for the UI's recovery blob
 *  write path. Per docs/RECOVERY_BLOB_FORMAT.md §8.3 and
 *  docs/RECOVERY_SPEC_V1_BACKEND_CHANGES.md §5, the UI compares its
 *  CURRENT_WRITE_SPEC_VERSION against minWriteSpecVersion before
 *  constructing a new blob; if the local client is behind, it prompts
 *  the user to update. This is the ONLY backend influence on client
 *  crypto behavior — it can refuse new writes, but it cannot dictate
 *  the protocol shape.
 *
 *  Auth: none. Public config. */
@RestController
@RequestMapping("/recovery/config")
public class RecoveryConfigHandler {

    private static final String MIN_WRITE_SPEC_VERSION = "v1";
    private static final String CURRENT_RECOMMENDED_SPEC_VERSION = "v1";
    private static final List<String> SUPPORTED_SPEC_VERSIONS_FOR_READ = List.of("v1");

    @GetMapping
    public ResponseEntity<ApiResponse<RecoveryConfigResponse>> config() {
        String requestId = UUID.randomUUID().toString();
        return ResponseEntity.ok(ApiResponse.ok(
                new RecoveryConfigResponse(
                        MIN_WRITE_SPEC_VERSION,
                        CURRENT_RECOMMENDED_SPEC_VERSION,
                        SUPPORTED_SPEC_VERSIONS_FOR_READ),
                requestId));
    }

    private record RecoveryConfigResponse(
            String minWriteSpecVersion,
            String currentRecommendedSpecVersion,
            List<String> supportedSpecVersionsForRead
    ) {}
}
