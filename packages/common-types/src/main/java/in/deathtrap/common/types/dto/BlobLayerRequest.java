package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** One layer in a layered recovery blob — describes a recipient's encryption contribution.
 *  Per docs/RECOVERY_BLOB_FORMAT.md §10, the client supplies only the metadata needed
 *  for peel orchestration; the backend resolves the active pubkey server-side via
 *  idx_pubkeys_active_party and verifies the supplied keyFingerprint matches
 *  SHA-256(SPKI DER) of the active pubkey. */
public record BlobLayerRequest(
        @NotBlank String partyId,
        @NotBlank String partyType,
        @NotBlank @Size(min = 64, max = 64) String keyFingerprint,
        @Min(1) int layerOrder
) {}
