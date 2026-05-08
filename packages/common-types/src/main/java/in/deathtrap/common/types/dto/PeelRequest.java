package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /recovery/session/{id}/peel — submits a peeled layer. */
public record PeelRequest(
        @NotBlank String intermediateCiphertextB64,
        String deviceFingerprint
) {}
