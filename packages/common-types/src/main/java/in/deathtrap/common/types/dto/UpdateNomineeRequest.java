package in.deathtrap.common.types.dto;

/** Request body for PATCH /auth/nominees/:id (Sprint A3).
 *  All fields optional — only non-null fields are applied. */
public record UpdateNomineeRequest(
        String fullName,
        String email,
        String mobile
) {}
