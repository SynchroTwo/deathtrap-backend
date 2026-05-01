package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for DELETE /auth/session. */
public record LogoutRequest(
        @NotNull String sessionId
) {}
