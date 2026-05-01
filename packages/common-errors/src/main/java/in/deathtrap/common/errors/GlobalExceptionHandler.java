package in.deathtrap.common.errors;

import in.deathtrap.common.types.api.ApiError;
import in.deathtrap.common.types.api.ApiResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Translates exceptions into structured JSON error responses. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** Handles application-level typed errors. */
    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiResponse<Void>> handleAppException(AppException ex) {
        String requestId = UUID.randomUUID().toString();
        log.warn("AppException: code={} requestId={}", ex.getErrorCode(), requestId);
        ApiError error = new ApiError(ex.getErrorCode().name(), ex.getErrorCode().getDefaultMessage(), ex.getDetails());
        return ResponseEntity
                .status(ex.getErrorCode().getHttpStatus())
                .body(ApiResponse.error(error, requestId));
    }

    /** Handles @Valid constraint violations on request bodies. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
        String requestId = UUID.randomUUID().toString();
        log.warn("Validation failed requestId={}", requestId);
        Map<String, Object> fieldErrors = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fe.getField(), fe.getDefaultMessage());
        }
        ApiError error = new ApiError(ErrorCode.VALIDATION_FAILED.name(),
                ErrorCode.VALIDATION_FAILED.getDefaultMessage(), fieldErrors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(error, requestId));
    }

    /** Handles all unexpected throwables — logs internally, never exposes details. */
    @ExceptionHandler(Throwable.class)
    public ResponseEntity<ApiResponse<Void>> handleAll(Throwable ex) {
        String requestId = UUID.randomUUID().toString();
        log.error("Unhandled exception requestId={}", requestId, ex);
        ApiError error = new ApiError(ErrorCode.INTERNAL_ERROR.name(),
                ErrorCode.INTERNAL_ERROR.getDefaultMessage(), null);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(error, requestId));
    }
}
