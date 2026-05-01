package in.deathtrap.common.response;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import in.deathtrap.common.types.api.ApiError;
import in.deathtrap.common.types.api.ApiResponse;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Builds Lambda APIGatewayProxyResponseEvent with security headers applied. */
public final class ResponseBuilder {

    private static final Logger log = LoggerFactory.getLogger(ResponseBuilder.class);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private static final Map<String, String> SECURITY_HEADERS = Map.of(
            "Content-Type", "application/json",
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains",
            "X-Frame-Options", "DENY",
            "X-Content-Type-Options", "nosniff",
            "Cache-Control", "no-store, no-cache, must-revalidate",
            "Pragma", "no-cache"
    );

    private ResponseBuilder() {}

    /** Returns a 200 OK response with the given data payload. */
    public static APIGatewayProxyResponseEvent ok(Object data, String requestId) {
        return build(200, ApiResponse.ok(data, requestId));
    }

    /** Returns a 201 Created response with the given data payload. */
    public static APIGatewayProxyResponseEvent created(Object data, String requestId) {
        return build(201, ApiResponse.ok(data, requestId));
    }

    /** Returns a 204 No Content response. */
    public static APIGatewayProxyResponseEvent noContent() {
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(204)
                .withHeaders(SECURITY_HEADERS)
                .withBody("");
    }

    /** Returns an error response derived from the given AppException. */
    public static APIGatewayProxyResponseEvent error(AppException ex, String requestId) {
        ApiError apiError = new ApiError(
                ex.getErrorCode().name(),
                ex.getErrorCode().getDefaultMessage(),
                ex.getDetails());
        return build(ex.getErrorCode().getHttpStatus(), ApiResponse.error(apiError, requestId));
    }

    /** Returns a 500 Internal Server Error response. */
    public static APIGatewayProxyResponseEvent internalError(String requestId) {
        ApiError apiError = new ApiError(
                ErrorCode.INTERNAL_ERROR.name(),
                ErrorCode.INTERNAL_ERROR.getDefaultMessage(),
                null);
        return build(500, ApiResponse.error(apiError, requestId));
    }

    private static APIGatewayProxyResponseEvent build(int statusCode, ApiResponse<?> response) {
        String body;
        try {
            body = MAPPER.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize response", e);
            body = "{\"success\":false,\"error\":{\"code\":\"INTERNAL_ERROR\"}}";
        }
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(statusCode)
                .withHeaders(SECURITY_HEADERS)
                .withBody(body);
    }
}
