package in.deathtrap.common.types.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

/** Request body for POST /recovery/blob — stores a layered recovery blob. */
public record StoreBlobRequest(
        @NotBlank String encryptedBlobB64,
        @NotNull @Size(min = 1) @Valid List<BlobLayerRequest> layers,
        @NotBlank String rebuildReason
) {}
