package com.devteria.identityservice.entity;

import java.time.Instant;
import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

/**
 * InvalidatedToken là một entity dùng để lưu các token đã bị vô hiệu hóa (logout) trong hệ thống.
 * Khi người dùng logout, token sẽ được lưu vào bảng này để tránh việc sử dụng lại token đã logout.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class InvalidatedToken {
    @Id
    String token;
    Date expiresTime;
}