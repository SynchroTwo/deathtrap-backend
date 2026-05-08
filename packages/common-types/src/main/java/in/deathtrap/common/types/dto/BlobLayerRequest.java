package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** One layer in a layered recovery blob — describes a party's encryption contribution. */
public record BlobLayerRequest(
        @NotBlank String partyId,
        @NotBlank String partyType,
        @NotBlank String pubkeyId,
        @NotBlank @Size(min = 64, max = 64) String keyFingerprint,
        @Min(1) int layerOrder
) {}
