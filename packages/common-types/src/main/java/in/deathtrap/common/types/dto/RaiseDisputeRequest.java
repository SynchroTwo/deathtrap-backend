package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for POST /recovery/dispute — raises a dispute to halt recovery. */
public record RaiseDisputeRequest(
        @NotBlank String sessionId,
        @NotBlank @Size(max = 1000) String reason
) {}
