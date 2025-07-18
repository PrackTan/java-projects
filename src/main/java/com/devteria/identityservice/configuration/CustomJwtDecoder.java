package com.devteria.identityservice.configuration;

import com.devteria.identityservice.dto.request.IntrospectRequest;
import com.devteria.identityservice.repository.InvalidatedTokenRepository;
import com.devteria.identityservice.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Objects;

/**
 * CustomJwtDecoder là một class dùng để giải mã (decode) và xác thực (validate) JWT token
 * trong hệ thống, implement interface JwtDecoder của Spring Security.
 * 
 * - Sử dụng AuthenticationService để kiểm tra tính hợp lệ của token (chữ ký, hạn dùng, bị vô hiệu hóa chưa).
 * - Nếu token hợp lệ, sử dụng NimbusJwtDecoder để giải mã token và trả về đối tượng Jwt.
 */
@Component
public class CustomJwtDecoder implements JwtDecoder {

    // Inject giá trị khóa bí mật từ file cấu hình (application.yaml)
    @Value("${jwt.signerKey}")
    private String signerKey;

    // Inject AuthenticationService để kiểm tra token
    @Autowired
    private AuthenticationService authenticationService;

    // Đối tượng NimbusJwtDecoder dùng để decode JWT, chỉ khởi tạo một lần (lazy init)
    private NimbusJwtDecoder nimbusJwtDecoder = null;

    /**
     * Phương thức decode nhận vào chuỗi token, kiểm tra hợp lệ và giải mã thành đối tượng Jwt.
     * @param token chuỗi JWT cần giải mã
     * @return đối tượng Jwt đã giải mã
     * @throws JwtException nếu token không hợp lệ
     */
    @Override
    public Jwt decode(String token) throws JwtException {
        // Bước 1: Kiểm tra tính hợp lệ của token bằng AuthenticationService
        try {
            var response = authenticationService.introspect(
                    IntrospectRequest.builder()
                            .token(token)
                            .build()
            );

            // Nếu token không hợp lệ, ném ra exception
            if (!response.isValid())
                throw new JwtException("Token invalid");
        } catch (JOSEException | ParseException e) {
            // Nếu có lỗi khi kiểm tra, ném ra exception
            throw new JwtException(e.getMessage());
        }

        // Bước 2: Khởi tạo NimbusJwtDecoder nếu chưa có (dùng thuật toán HS512)
        if (Objects.isNull(nimbusJwtDecoder)) {
            SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
            nimbusJwtDecoder = NimbusJwtDecoder
                    .withSecretKey(secretKeySpec)
                    .macAlgorithm(MacAlgorithm.HS512)
                    .build();
        }

        // Bước 3: Giải mã token thành đối tượng Jwt và trả về
        return nimbusJwtDecoder.decode(token);
    }
}