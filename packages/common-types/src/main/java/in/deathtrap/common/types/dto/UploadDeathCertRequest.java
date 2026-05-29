package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

/** Request body for POST /recovery/death-cert (E006 Phase 1).
 *
 *  The caller (trustee for Model A, any nominee for Model B) uploads a soft
 *  copy of the creator's death certificate. Cert bytes are base64-encoded in
 *  the request body to stay within API Gateway / Lambda payload limits without
 *  needing a separate presigned-URL hop in Phase 1; the BE decodes once and
 *  writes the raw bytes to S3 at recovery/death-certs/{creatorId}/{certId}.
 *
 *  Fields:
 *   - creatorId: target creator (verified against the caller's nominee link).
 *   - certB64:   base64-encoded cert bytes (jpeg / png / pdf).
 *   - mimeType:  one of "image/jpeg", "image/png", "application/pdf".
 *   - sizeBytes: decoded binary size, validated against the DB CHECK
 *                (0 < size <= 10485760) and matched against base64 length.
 *   - contentHashSha256: 64 hex chars; integrity check (matched against
 *                the decoded bytes server-side).
 *
 *  See docs ClaudeOutput/E006_BACKEND_CONTRACT.md §8. */
public record UploadDeathCertRequest(
        @NotBlank String creatorId,
        @NotBlank String certB64,
        @NotBlank String mimeType,
        @Positive long sizeBytes,
        @NotBlank @Pattern(regexp = "^[0-9a-f]{64}$") String contentHashSha256
) {}
