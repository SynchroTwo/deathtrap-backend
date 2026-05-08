package in.deathtrap.common.types.dto;

import java.time.Instant;

/** Response body for POST /auth/nominee/invite. */
public record NomineeInviteResponse(String nomineeId, Instant inviteExpiresAt) {}
