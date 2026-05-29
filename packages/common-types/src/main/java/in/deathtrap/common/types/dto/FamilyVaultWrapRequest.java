package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Request body for POST /locker/family-vault/wraps (E011 Phase 1A).
 *
 *  The creator constructs an ECDH wrap of their lockerKey to each nominee's
 *  active pubkey and POSTs it here. Server stores opaque envelope bytes;
 *  never decrypts. Envelope shape mirrors recovery_blob_layers so the FE
 *  reuses the same ECDH/HKDF/AES-GCM primitives.
 *
 *  See ClaudeOutput/E011_BACKEND_CONTRACT.md §3.1. */
public record FamilyVaultWrapRequest(
        @NotBlank @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            String wrapId,
        @NotBlank String nomineePartyId,
        @NotBlank String specVersion,
        @NotBlank @Pattern(regexp = "^[0-9a-f]{64}$") String saltHex,
        @NotBlank @Pattern(regexp = "^[0-9a-f]{64}$") String keyFingerprint,
        @NotBlank String ephPubkeyB64,
        @NotBlank String nonceB64,
        @NotBlank String ciphertextB64,
        @NotBlank String authTagB64
) {}
