package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for PATCH /recovery/dispute/{id} — admin resolves a dispute. */
public record ResolveDisputeRequest(
        @NotBlank String resolution,
        @Size(max = 2000) String notes
) {}
