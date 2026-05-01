package in.deathtrap.common.types.api;

/** Generic API response wrapper used across all services. */
public record ApiResponse<T>(
        boolean success,
        T data,
        ApiError error,
        String requestId
) {
    /** Returns a successful response wrapping the given data. */
    public static <T> ApiResponse<T> ok(T data, String requestId) {
        return new ApiResponse<>(true, data, null, requestId);
    }

    /** Returns an error response wrapping the given ApiError. */
    public static <T> ApiResponse<T> error(ApiError error, String requestId) {
        return new ApiResponse<>(false, null, error, requestId);
    }
}
