package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for assigning a nominee to a locker asset. */
public record NomineeAssignRequest(
        @NotBlank String assetId,
        @NotBlank String nomineeId
) {}
