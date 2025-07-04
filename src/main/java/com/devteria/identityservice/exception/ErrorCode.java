package com.devteria.identityservice.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
public enum ErrorCode {
    // 1000 - 1999: Authentication and Authorization
    // 2000 - 2999: User Management
    // 3000 - 3999: Role Management
    // 4000 - 4999: Permission Management
    // 5000 - 5999: Token Management
    // 6000 - 6999: Session Management
    // 7000 - 7999: Audit Management
    UNCATEGORIZED_EXCEPTION(9999, "An uncategorized error has occurred", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY(1001, "The provided key is invalid", HttpStatus.BAD_REQUEST),
    USER_EXISTED(1002, "The user already exists in the system", HttpStatus.BAD_REQUEST),
    USERNAME_INVALID(1003, "The username must be at least {min} characters long", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(1004, "The password must be at least {min} characters long", HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(1005, "The specified user does not exist", HttpStatus.NOT_FOUND),
    UNAUTHENTICATED(1006, "User is not authenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1007, "User does not have the necessary permissions", HttpStatus.FORBIDDEN),
    EMAIL_INVALID(1008, "The email format provided is invalid", HttpStatus.BAD_REQUEST),
    ACCOUNT_LOCKED(1009, "The account has been locked due to multiple failed login attempts", HttpStatus.FORBIDDEN),
    TOKEN_EXPIRED(1010, "The authentication token has expired", HttpStatus.UNAUTHORIZED),
    ACCESS_DENIED(1011, "Access to the requested resource is denied", HttpStatus.FORBIDDEN),
    RESOURCE_NOT_FOUND(1012, "The requested resource could not be found", HttpStatus.NOT_FOUND),
    METHOD_NOT_ALLOWED(1013, "The HTTP method used is not allowed for this endpoint", HttpStatus.METHOD_NOT_ALLOWED),
    INTERNAL_SERVER_ERROR(1014, "An internal server error has occurred", HttpStatus.INTERNAL_SERVER_ERROR),
    BAD_REQUEST(1015, "The request could not be understood or was missing required parameters", HttpStatus.BAD_REQUEST),
    INVALID_DOB(1016, "Your age must be at least {min} ", HttpStatus.BAD_REQUEST),
    ;
    ErrorCode(int code, String message, HttpStatusCode statusCode) {
        this.code = code;
        this.message = message;
        this.statusCode = statusCode;
    }

    private int code;
    private String message;
    private HttpStatusCode statusCode;

}
