package in.deathtrap.common.types.api;

import java.util.Map;

/** Structured error payload returned in all error responses. */
public record ApiError(
        String code,
        String message,
        Map<String, Object> details
) {}
