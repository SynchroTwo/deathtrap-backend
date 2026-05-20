package in.deathtrap.common.types.dto;

/** Response for GET /auth/nominees/:id/pubkey and GET /auth/creator/:id/pubkey.
 *  fingerprint is the lowercase hex SHA-256 of the SPKI DER. */
public record PubkeyView(
        String pubkeyPem,
        String fingerprint
) {}
