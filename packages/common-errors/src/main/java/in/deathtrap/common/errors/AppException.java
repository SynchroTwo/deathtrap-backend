package in.deathtrap.common.errors;

import java.time.Instant;
import java.util.Map;

/** Runtime exception carrying a typed error code and optional structured details. */
public class AppException extends RuntimeException {

    private final ErrorCode errorCode;
    private final Map<String, Object> details;

    /** Constructs an AppException with only an error code. */
    public AppException(ErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
        this.details = null;
    }

    /** Constructs an AppException with an error code and an additional message. */
    public AppException(ErrorCode errorCode, String additionalMessage) {
        super(additionalMessage);
        this.errorCode = errorCode;
        this.details = null;
    }

    /** Constructs an AppException with an error code and structured details. */
    public AppException(ErrorCode errorCode, Map<String, Object> details) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
        this.details = details;
    }

    /** Returns the typed error code. */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /** Returns optional structured details, may be null. */
    public Map<String, Object> getDetails() {
        return details;
    }

    // --- Static factory methods ---

    /** Returns an exception for an invalid OTP. */
    public static AppException otpInvalid() {
        return new AppException(ErrorCode.AUTH_OTP_INVALID);
    }

    /** Returns an exception for an expired OTP. */
    public static AppException otpExpired() {
        return new AppException(ErrorCode.AUTH_OTP_EXPIRED);
    }

    /** Returns an exception for a locked OTP with the unlock time. */
    public static AppException otpLocked(Instant lockedUntil) {
        return new AppException(ErrorCode.AUTH_OTP_LOCKED,
                Map.of("lockedUntil", lockedUntil.toString()));
    }

    /** Returns an exception for an invalid session. */
    public static AppException sessionInvalid() {
        return new AppException(ErrorCode.AUTH_SESSION_INVALID);
    }

    /** Returns an exception for an expired session. */
    public static AppException sessionExpired() {
        return new AppException(ErrorCode.AUTH_SESSION_EXPIRED);
    }

    /** Returns an exception for a revoked session. */
    public static AppException sessionRevoked() {
        return new AppException(ErrorCode.AUTH_SESSION_REVOKED);
    }

    /** Returns an exception for an unauthenticated request. */
    public static AppException unauthorized() {
        return new AppException(ErrorCode.AUTH_UNAUTHORIZED);
    }

    /** Returns an exception for a forbidden operation. */
    public static AppException forbidden() {
        return new AppException(ErrorCode.AUTH_FORBIDDEN);
    }

    /** Returns an exception for KYC failure. */
    public static AppException kycFailed() {
        return new AppException(ErrorCode.AUTH_KYC_FAILED);
    }

    /** Returns an exception for a duplicate registration on the given field. */
    public static AppException registrationDuplicate(String field) {
        return new AppException(ErrorCode.AUTH_REGISTRATION_DUPLICATE,
                Map.of("field", field));
    }

    /** Returns an exception for an invalid invite token. */
    public static AppException inviteInvalid() {
        return new AppException(ErrorCode.AUTH_INVITE_INVALID);
    }

    /** Returns an exception for an expired invite. */
    public static AppException inviteExpired() {
        return new AppException(ErrorCode.AUTH_INVITE_EXPIRED);
    }

    /** Returns an exception for an unknown nominee referenced by an invite or path id. */
    public static AppException nomineeNotFound() {
        return new AppException(ErrorCode.NOMINEE_NOT_FOUND);
    }

    /** Returns an exception when a nominee has already accepted their invite. */
    public static AppException nomineeAlreadyRegistered() {
        return new AppException(ErrorCode.NOMINEE_ALREADY_REGISTERED);
    }

    /** Returns an exception indicating a compromised passphrase. */
    public static AppException passphraseCompromised() {
        return new AppException(ErrorCode.AUTH_PASSPHRASE_COMPROMISED);
    }

    /** Returns an exception for a validation failure. */
    public static AppException validationFailed(Map<String, Object> fieldErrors) {
        return new AppException(ErrorCode.VALIDATION_FAILED, fieldErrors);
    }

    /** Returns an exception for a not-found resource. */
    public static AppException notFound(String resource) {
        return new AppException(ErrorCode.NOT_FOUND, Map.of("resource", resource));
    }

    /** Returns an exception for a generic conflict. */
    public static AppException conflict(String detail) {
        return new AppException(ErrorCode.CONFLICT, Map.of("detail", detail));
    }

    /** Returns an exception for an internal server error. */
    public static AppException internalError() {
        return new AppException(ErrorCode.INTERNAL_ERROR);
    }

    /** Returns an exception for an external service failure. */
    public static AppException externalServiceError() {
        return new AppException(ErrorCode.EXTERNAL_SERVICE_ERROR);
    }

    /** Returns an exception for rate limiting. */
    public static AppException rateLimited() {
        return new AppException(ErrorCode.RATE_LIMITED);
    }

    /** Returns an exception for OTP-specific rate limiting. */
    public static AppException otpRateLimited() {
        return new AppException(ErrorCode.OTP_RATE_LIMITED);
    }

    /** Returns an exception for an invalid or expired verified-OTP token. */
    public static AppException invalidVerifiedToken() {
        return new AppException(ErrorCode.AUTH_INVALID_VERIFIED_TOKEN);
    }

    /** Returns an exception for a locker blob optimistic-lock conflict. */
    public static AppException lockerVersionConflict(int expectedVersion, int actualVersion) {
        return new AppException(ErrorCode.LOCKER_VERSION_CONFLICT,
                Map.of("expectedVersion", expectedVersion, "actualVersion", actualVersion));
    }

    /** Returns an exception for a recovery session that is in disputed state. */
    public static AppException recoverySessionDisputed(String detail) {
        return new AppException(ErrorCode.RECOVERY_SESSION_DISPUTED, Map.of("detail", detail));
    }

    /** Returns an exception when a trigger lacks the required confirming signal sources. */
    public static AppException triggerInsufficientSources(int received, int required) {
        return new AppException(ErrorCode.TRIGGER_INSUFFICIENT_SOURCES,
                Map.of("sourcesReceived", received, "sourcesRequired", required));
    }

    // --- Recovery blob format v1 factories ---

    /** Returns an exception when the client's recovery blob spec version is not supported. */
    public static AppException recoveryUnsupportedSpecVersion(String supplied, java.util.List<String> supported) {
        return new AppException(ErrorCode.RECOVERY_UNSUPPORTED_SPEC_VERSION,
                Map.of("supplied", supplied, "supported", supported));
    }

    /** Returns an exception when the recipient list does not start with a lawyer or includes non-nominee layers. */
    public static AppException recoveryInvalidRecipientOrder(String detail) {
        return new AppException(ErrorCode.RECOVERY_INVALID_RECIPIENT_ORDER, Map.of("detail", detail));
    }

    /** Returns an exception when the recipient count is outside [2, 7]. */
    public static AppException recoveryLayerCountOutOfBounds(int supplied) {
        return new AppException(ErrorCode.RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS,
                Map.of("supplied", supplied, "min", 2, "max", 7));
    }

    /** Returns an exception when a referenced recipient is not owned by the creator. */
    public static AppException recoveryUnknownRecipient(String partyId, String partyType) {
        return new AppException(ErrorCode.RECOVERY_UNKNOWN_RECIPIENT,
                Map.of("partyId", partyId, "partyType", partyType));
    }

    /** Returns an exception when the client-supplied keyFingerprint does not match the active pubkey. */
    public static AppException recoveryStaleRecipientKey(
            String partyId, String partyType, String currentFingerprint, String providedFingerprint) {
        return new AppException(ErrorCode.RECOVERY_STALE_RECIPIENT_KEY, Map.of(
                "partyId", partyId,
                "partyType", partyType,
                "currentFingerprint", currentFingerprint,
                "providedFingerprint", providedFingerprint));
    }

    /** Returns an exception when the same partyId appears twice in the recipient list. */
    public static AppException recoveryDuplicateRecipient(String partyId) {
        return new AppException(ErrorCode.RECOVERY_DUPLICATE_RECIPIENT, Map.of("partyId", partyId));
    }

    /** Returns an exception when layerOrder values are not a dense 1..N permutation. */
    public static AppException recoveryInvalidLayerOrdering(String detail) {
        return new AppException(ErrorCode.RECOVERY_INVALID_LAYER_ORDERING, Map.of("detail", detail));
    }

    /** Returns an exception when the encrypted blob exceeds the size cap. */
    public static AppException recoveryBlobTooLarge(int suppliedBytes, int maxBytes) {
        return new AppException(ErrorCode.RECOVERY_BLOB_TOO_LARGE,
                Map.of("suppliedBytes", suppliedBytes, "maxBytes", maxBytes));
    }
}
