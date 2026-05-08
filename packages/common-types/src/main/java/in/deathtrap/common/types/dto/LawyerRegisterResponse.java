package in.deathtrap.common.types.dto;

/** Response body for POST /auth/lawyer/register. */
public record LawyerRegisterResponse(String lawyerId, String status, String message) {}
