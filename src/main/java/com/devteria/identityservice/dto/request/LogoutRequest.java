package com.devteria.identityservice.dto.request;

import lombok.Data;

@Data
public class LogoutRequest {
    String token;
}