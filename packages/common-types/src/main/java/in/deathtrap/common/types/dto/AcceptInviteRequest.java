package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /auth/nominee/accept (Sprint A3, path A).
 *  The nominee submits the creator-signed invite token plus their own freshly
 *  generated crypto material. The backend verifies the token's ECDSA signature
 *  against the creator's stored pubkey before creating the nominee identity. */
public record AcceptInviteRequest(
        /** base64url single-string token: base64url(canonicalJson({payload, signature})). */
        @NotBlank String inviteToken,
        /** The nominee's newly generated ECDH-P256 public key (SPKI PEM). */
        @NotBlank String pubkeyPem,
        /** AES-GCM ciphertext of the nominee's privkey (base64). */
        @NotBlank String encryptedPrivkeyB64,
        /** 12-byte GCM nonce (base64). */
        @NotBlank String encryptedPrivkeyNonceB64,
        /** 16-byte GCM auth tag (base64). */
        @NotBlank String encryptedPrivkeyTagB64,
        /** Argon2id salt for the nominee's KDF (base64). */
        @NotBlank String saltB64
) {}
