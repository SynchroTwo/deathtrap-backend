package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /auth/nominees (Sprint A3, path A).
 *  Creates a nominee record in status='invited'. The signed invite token is
 *  generated client-side after this returns the server-assigned nomineeId.
 *  email / mobile are optional (nullable) per the A3 contract. */
public record CreateNomineeRequest(
        @NotBlank String fullName,
        String email,
        String mobile,
        /** Token expiry hint (ISO 8601). Server stores it; client bakes it into the signed token. */
        String expiresAt
) {}
