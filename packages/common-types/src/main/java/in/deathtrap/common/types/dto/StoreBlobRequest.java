package in.deathtrap.common.types.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

/** Request body for POST /recovery/blob — stores a layered recovery blob.
 *  v1 wire format (docs/RECOVERY_BLOB_FORMAT.md §10 / BACKEND_CHANGES §3.1):
 *   - specVersion: must equal "v1" today; backend validates against the
 *     supported set and returns RECOVERY_UNSUPPORTED_SPEC_VERSION on mismatch.
 *   - blobId: client-generated UUID v4 so the UI can correlate before the
 *     response arrives. Stored verbatim in recovery_blobs.blob_id.
 *   - encryptedBlobB64: opaque base64-encoded envelope bytes. Backend never
 *     inspects the contents; max 32 KB per RECOVERY_BLOB_TOO_LARGE.
 *   - rebuildReason: must be one of the documented enum values; tightened
 *     beyond @NotBlank by StoreBlobHandler.
 *   - layers: 2..7 elements, layerOrder is dense 1..N, first element must
 *     be the lawyer, rest must be nominees. */
public record StoreBlobRequest(
        @NotBlank String specVersion,
        @NotBlank String blobId,
        @NotBlank String encryptedBlobB64,
        @NotNull @Size(min = 1) @Valid List<BlobLayerRequest> layers,
        @NotBlank String rebuildReason
) {}
