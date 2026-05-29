package in.deathtrap.common.types.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

/** Request body for POST /recovery/blob — stores a layered recovery blob.
 *
 *  Accepts both v1 (legacy) and v2 (E006) wire formats:
 *   - specVersion: "v1" or "v2". Backend validates against the supported set
 *     and returns RECOVERY_UNSUPPORTED_SPEC_VERSION on mismatch.
 *   - blobId: client-generated UUID v4 so the UI can correlate before the
 *     response arrives. Stored verbatim in recovery_blobs.blob_id.
 *   - encryptedBlobB64: opaque base64-encoded envelope bytes. Backend never
 *     inspects the contents; max 32 KB per RECOVERY_BLOB_TOO_LARGE.
 *   - rebuildReason: must be one of the documented enum values; tightened
 *     beyond @NotBlank by StoreBlobHandler.
 *   - recoveryShape: nullable — required for v2, ignored for v1. Values:
 *     "sequential" (Model A, nested-doll trustees, 1..3 layers) or "parallel"
 *     (Model B, N independent wraps, Phase 2 only).
 *   - layers: 2..7 elements for v1 (lawyer-then-nominees), 1..3 elements for
 *     v2 sequential (trustees only). layerOrder is dense 1..N.
 *
 *  v1 spec: docs/RECOVERY_BLOB_FORMAT.md.
 *  v2 spec: docs/RECOVERY_BLOB_FORMAT_V2.md + ClaudeOutput/E006_BACKEND_CONTRACT.md §2-§4. */
public record StoreBlobRequest(
        @NotBlank String specVersion,
        @NotBlank String blobId,
        @NotBlank String encryptedBlobB64,
        @NotNull @Size(min = 1) @Valid List<BlobLayerRequest> layers,
        @NotBlank String rebuildReason,
        String recoveryShape
) {}
