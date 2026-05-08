package in.deathtrap.common.types.dto;

/** JSON payload placed on the SQS trigger queue by trigger-service or inactivity scanner. */
public record TriggerMessage(
        String event,
        String creatorId,
        String sourceType,
        String referenceId,
        String partyId,
        String partyType,
        String reason
) {}
