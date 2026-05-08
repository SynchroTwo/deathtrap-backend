package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** A single nominee assignment update from the WatermelonDB push sync. */
public record NomineeAssignmentUpdate(
        @NotBlank String assignmentId,
        String officialNominationStatus,
        Integer displayOrder,
        @Size(max = 500) String notes
) {}
