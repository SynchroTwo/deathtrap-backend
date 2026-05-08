package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;
import java.time.LocalDate;

/** Request body for POST /auth/register. */
public record RegisterCreatorRequest(
        @NotNull String fullName,
        @NotNull LocalDate dateOfBirth,
        @NotNull String mobile,
        @NotNull String email,
        String address,
        String aadhaarRef,
        String kycProviderRef,
        String hibpPrefix,
        String hibpSuffix,
        boolean hibpCheckResult,
        int entropyBits,
        @NotNull String publicKeyPem,
        @NotNull String keyFingerprint,
        @NotNull String encryptedPrivkeyB64,
        @NotNull String nonceB64,
        @NotNull String authTagB64,
        @NotNull String saltHex,
        int schemaVersion,
        int inactivityTriggerMonths
) {}
