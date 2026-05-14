package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/register/init.
 *  Kicks off registration by validating mobile+email format/uniqueness and
 *  sending OTPs to both channels in one server-side call. */
public record RegisterInitRequest(
        @NotNull String mobile,
        @NotNull String email
) {}
