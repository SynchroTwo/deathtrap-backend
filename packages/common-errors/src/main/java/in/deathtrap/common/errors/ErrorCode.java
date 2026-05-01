package in.deathtrap.common.errors;

/** All application-level error codes with HTTP status and default message. */
public enum ErrorCode {

    // Auth
    AUTH_OTP_INVALID(400, "OTP is invalid"),
    AUTH_OTP_EXPIRED(400, "OTP has expired"),
    AUTH_OTP_LOCKED(429, "Too many failed attempts. OTP locked."),
    AUTH_SESSION_INVALID(401, "Session is invalid"),
    AUTH_SESSION_EXPIRED(401, "Session has expired"),
    AUTH_SESSION_REVOKED(401, "Session has been revoked"),
    AUTH_UNAUTHORIZED(401, "Authentication required"),
    AUTH_FORBIDDEN(403, "Access denied"),
    AUTH_KYC_FAILED(422, "KYC verification failed"),
    AUTH_REGISTRATION_DUPLICATE(409, "Account already exists"),
    AUTH_INVITE_INVALID(400, "Invite token is invalid"),
    AUTH_INVITE_EXPIRED(410, "Invite has expired"),
    AUTH_PASSPHRASE_COMPROMISED(422, "This passphrase has appeared in known data breaches"),

    // Validation
    VALIDATION_FAILED(400, "Validation failed"),

    // Resource
    NOT_FOUND(404, "Resource not found"),
    CONFLICT(409, "Conflict"),

    // Server
    INTERNAL_ERROR(500, "An unexpected error occurred"),
    EXTERNAL_SERVICE_ERROR(502, "External service unavailable"),
    RATE_LIMITED(429, "Too many requests");

    private final int httpStatus;
    private final String defaultMessage;

    ErrorCode(int httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    /** Returns the HTTP status code associated with this error. */
    public int getHttpStatus() {
        return httpStatus;
    }

    /** Returns the default human-readable message for this error. */
    public String getDefaultMessage() {
        return defaultMessage;
    }
}
