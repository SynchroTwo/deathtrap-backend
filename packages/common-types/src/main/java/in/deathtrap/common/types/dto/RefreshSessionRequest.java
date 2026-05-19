package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /auth/session/refresh.
 *  The refresh token issued by /auth/session or /auth/register is exchanged
 *  for a fresh access token. The refresh token authenticates the request;
 *  no Authorization header is required. */
public record RefreshSessionRequest(
        @NotBlank String refreshToken
) {}
