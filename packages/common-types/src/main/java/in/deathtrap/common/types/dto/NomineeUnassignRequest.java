package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for removing a nominee assignment from a locker asset. */
public record NomineeUnassignRequest(@NotBlank String assignmentId) {}
