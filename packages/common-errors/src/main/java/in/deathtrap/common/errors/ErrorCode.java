package in.deathtrap.common.errors;

/** All application-level error codes with HTTP status and default message. */
public enum ErrorCode {

    // Auth
    AUTH_OTP_INVALID(400, "OTP is invalid"),
    AUTH_OTP_EXPIRED(400, "OTP has expired"),
    AUTH_OTP_LOCKED(429, "Too many failed attempts. OTP locked."),
    OTP_RATE_LIMITED(429, "Too many OTP requests"),
    AUTH_SESSION_INVALID(401, "Session is invalid"),
    AUTH_SESSION_EXPIRED(401, "Session has expired"),
    AUTH_SESSION_REVOKED(401, "Session has been revoked"),
    AUTH_INVALID_VERIFIED_TOKEN(401, "Verified-OTP token is invalid or expired"),
    AUTH_UNAUTHORIZED(401, "Authentication required"),
    AUTH_FORBIDDEN(403, "Access denied"),
    AUTH_KYC_FAILED(422, "KYC verification failed"),
    AUTH_REGISTRATION_DUPLICATE(409, "Account already exists"),
    AUTH_INVITE_INVALID(400, "Invite token is invalid"),
    AUTH_INVITE_EXPIRED(410, "Invite has expired"),
    NOMINEE_NOT_FOUND(404, "Nominee not found"),
    NOMINEE_ALREADY_REGISTERED(409, "Nominee has already accepted this invite"),
    AUTH_PASSPHRASE_COMPROMISED(422, "This passphrase has appeared in known data breaches"),

    // Validation
    VALIDATION_FAILED(400, "Validation failed"),

    // Resource
    NOT_FOUND(404, "Resource not found"),
    CONFLICT(409, "Conflict"),
    LOCKER_VERSION_CONFLICT(409, "Locker blob version conflict"),
    RECOVERY_SESSION_DISPUTED(409, "Recovery session is disputed"),

    // Recovery blob format v1 (see docs/RECOVERY_BLOB_FORMAT.md)
    RECOVERY_UNSUPPORTED_SPEC_VERSION(400, "Unsupported recovery blob spec version"),
    RECOVERY_INVALID_RECIPIENT_ORDER(400, "Recovery blob recipient ordering invalid (lawyer must be layerOrder=1, all others nominees)"),
    RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS(400, "Recovery blob layer count out of bounds (must be 2..7)"),
    RECOVERY_UNKNOWN_RECIPIENT(400, "Recovery blob references an unknown recipient for this creator"),
    RECOVERY_STALE_RECIPIENT_KEY(400, "Recovery blob recipient key fingerprint does not match the recipient's active pubkey"),
    RECOVERY_DUPLICATE_RECIPIENT(400, "Recovery blob has a duplicate recipient party"),
    RECOVERY_INVALID_LAYER_ORDERING(400, "Recovery blob layer ordering is not dense and 1-indexed"),
    RECOVERY_BLOB_TOO_LARGE(413, "Recovery blob exceeds the 32 KB size limit"),

    // Trigger
    TRIGGER_INSUFFICIENT_SOURCES(400, "Insufficient signal sources for trigger"),

    // E006 — death-cert + confirmation flow
    RECOVERY_COOLOFF_ACTIVE(409, "Recovery confirmation cycle is in cooloff"),
    RECOVERY_FORBIDDEN_RELATION(403, "Caller is not authorised to act for this creator"),
    RECOVERY_INVALID_MIME(400, "Death certificate mime type not allowed"),
    RECOVERY_FILE_TOO_LARGE(413, "Death certificate exceeds the size limit"),
    RECOVERY_TOKEN_MISSING(401, "Action-link token missing"),
    RECOVERY_TOKEN_ALREADY_USED(409, "Action-link token has already been used"),
    RECOVERY_WINDOW_OBJECTED(409, "Confirmation window has already been objected"),
    RECOVERY_WINDOW_CONFIRMED(409, "Confirmation window has already been confirmed"),

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
