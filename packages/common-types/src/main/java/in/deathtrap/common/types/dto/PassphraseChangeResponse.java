package in.deathtrap.common.types.dto;

/** Response body for POST /auth/passphrase/change. */
public record PassphraseChangeResponse(String message, int newKeyVersion) {}
