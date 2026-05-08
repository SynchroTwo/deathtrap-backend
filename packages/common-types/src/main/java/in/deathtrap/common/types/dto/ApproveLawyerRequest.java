package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /auth/lawyer/approve. */
public record ApproveLawyerRequest(@NotBlank String lawyerId) {}
