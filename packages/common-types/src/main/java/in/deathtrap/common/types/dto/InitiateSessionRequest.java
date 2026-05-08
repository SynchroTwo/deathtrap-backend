package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /recovery/session — initiates a recovery session. */
public record InitiateSessionRequest(@NotBlank String creatorId) {}
