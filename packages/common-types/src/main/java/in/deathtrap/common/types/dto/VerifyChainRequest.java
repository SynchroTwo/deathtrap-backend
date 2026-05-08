package in.deathtrap.common.types.dto;

/** Request body for POST /audit/verify — optional start anchor for hash chain verification. */
public record VerifyChainRequest(String fromAuditId) {}
