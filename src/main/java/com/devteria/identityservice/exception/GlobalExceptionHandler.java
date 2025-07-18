package com.devteria.identityservice.exception;

import com.devteria.identityservice.dto.request.ApiResponse;

import jakarta.validation.ConstraintViolation;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Objects;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * GlobalExceptionHandler là một class dùng để xử lý các exception (ngoại lệ) toàn cục trong ứng dụng Spring Boot.
 * Class này sẽ bắt các exception được ném ra trong quá trình xử lý request và trả về response phù hợp cho client.
 */
@ControllerAdvice // Đánh dấu đây là một class xử lý exception toàn cục
@Slf4j // Tự động tạo logger cho class
public class GlobalExceptionHandler {
    // Định nghĩa tên các thuộc tính dùng để lấy giá trị minAge và maxAge từ annotation validate
    private static final String MIN_ATTRIBUTE = "minAge";
    private static final String MAX_ATTRIBUTE = "maxAge";

    /**
     * Xử lý tất cả các exception kiểu RuntimeException (bao gồm Exception nói chung).
     * Trả về response với mã lỗi và message mặc định cho lỗi không xác định.
     */
    @ExceptionHandler(value = Exception.class)
    ResponseEntity<ApiResponse> handlingRuntimeException(RuntimeException exception){
        log.error("Exception: ", exception); // Ghi log lỗi
        ApiResponse apiResponse = new ApiResponse();

        apiResponse.setCode(ErrorCode.UNCATEGORIZED_EXCEPTION.getCode());
        apiResponse.setMessage(ErrorCode.UNCATEGORIZED_EXCEPTION.getMessage());

        return ResponseEntity.badRequest().body(apiResponse); // Trả về response 400 Bad Request
    }

    /**
     * Xử lý các exception do ứng dụng tự định nghĩa (AppException).
     * Lấy mã lỗi và message từ ErrorCode của exception và trả về cho client.
     */
    @ExceptionHandler(value = AppException.class)
    ResponseEntity<ApiResponse> handlingAppException(AppException exception){
        ErrorCode errorCode = exception.getErrorCode();
        ApiResponse apiResponse = new ApiResponse();

        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());

        return ResponseEntity
                .status(errorCode.getStatusCode()) // Trả về status code tương ứng với lỗi
                .body(apiResponse);
    }

    /**
     * Xử lý exception khi người dùng không có quyền truy cập (AccessDeniedException).
     * Trả về mã lỗi UNAUTHORIZED cho client.
     */
    @ExceptionHandler(value = AccessDeniedException.class)
    ResponseEntity<ApiResponse> handlingAccessDeniedException(AccessDeniedException exception){
        ErrorCode errorCode = ErrorCode.UNAUTHORIZED;

        return ResponseEntity.status(errorCode.getStatusCode()).body(
                ApiResponse.builder()
                        .code(errorCode.getCode())
                        .message(errorCode.getMessage())
                        .build()
        );
    }

    /**
     * Xử lý exception khi validate dữ liệu đầu vào thất bại (MethodArgumentNotValidException).
     * Lấy message lỗi từ annotation validate, ánh xạ sang ErrorCode tương ứng.
     * Nếu có các thuộc tính như minAge, maxAge thì thay thế vào message trả về.
     */
    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    ResponseEntity<ApiResponse> handlingValidation(MethodArgumentNotValidException exception){
        // Lấy key của enum ErrorCode từ message của field bị lỗi
        String enumKey = exception.getFieldError().getDefaultMessage();

        ErrorCode errorCode = ErrorCode.INVALID_KEY; // Mặc định là INVALID_KEY
        Map<String,Object> attributes = null;
        try {
            // Thử ánh xạ enumKey sang ErrorCode
            errorCode = ErrorCode.valueOf(enumKey);
            // Lấy thông tin về các ràng buộc validate (ví dụ: minAge, maxAge)
            var constraintViolations = exception.getBindingResult().getAllErrors().getFirst().unwrap(ConstraintViolation.class);
            attributes = constraintViolations.getConstraintDescriptor().getAttributes();
            log.info("Attributes: {}", attributes);
        } catch (IllegalArgumentException e){
            // Nếu enumKey không hợp lệ thì giữ nguyên INVALID_KEY
        }

        ApiResponse apiResponse = new ApiResponse();

        apiResponse.setCode(errorCode.getCode());
        // Nếu có attributes thì thay thế {min}, {max} trong message, ngược lại trả về message gốc
        apiResponse.setMessage(Objects.nonNull(attributes) ? mapAttribute(errorCode.getMessage(), attributes) : errorCode.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }

    /**
     * Hàm hỗ trợ thay thế giá trị {min} và {max} trong message bằng giá trị thực tế từ attributes.
     */
    private String mapAttribute(String message, Map<String,Object> attributes){
        String minValue = String.valueOf(attributes.get(MIN_ATTRIBUTE));
        String maxValue = String.valueOf(attributes.get(MAX_ATTRIBUTE));

        return message.replace("{min}", minValue).replace("{max}", maxValue);
    }
}
