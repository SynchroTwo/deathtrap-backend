package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Payload sent by an external death registry or municipality system to POST /trigger/event. */
public record DeathEventWebhookRequest(
        @NotBlank String creatorMobile,
        @NotBlank String sourceType,
        @NotBlank String referenceId,
        @NotBlank String reportedAt
) {}
