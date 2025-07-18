package com.devteria.identityservice.configuration;

import com.devteria.identityservice.enums.Role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {


    @Autowired
    private CustomJwtDecoder customJwtDecoder;

    private final String[] PUBLIC_ENDPOINTS = {"/users",
            "/auth/token", "/auth/introspect", "/auth/logout"
    };

    // @Value("${jwt.signerKey}")
    // private String signerKey;

    /**
     * Định nghĩa bean SecurityFilterChain để cấu hình bảo mật cho ứng dụng.
     * @param httpSecurity đối tượng HttpSecurity để cấu hình các rule bảo mật
     * @return SecurityFilterChain đã được cấu hình
     * @throws Exception nếu có lỗi xảy ra trong quá trình cấu hình
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // Cấu hình quyền truy cập cho các endpoint
        httpSecurity.authorizeHttpRequests(request ->
                // Cho phép tất cả mọi người truy cập các endpoint trong PUBLIC_ENDPOINTS với phương thức POST
                request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll()
                        // Các request còn lại phải xác thực (authenticated)
                        .anyRequest().authenticated());

        // Cấu hình resource server sử dụng JWT để xác thực
        httpSecurity.oauth2ResourceServer(oauth2 ->
                // Cấu hình xác thực JWT
                oauth2.jwt(jwtConfigurer ->
                        // Sử dụng bean jwtDecoder() để giải mã JWT
                        jwtConfigurer.decoder(customJwtDecoder)
                                // Sử dụng jwtAuthenticationConverter() để chuyển đổi thông tin xác thực từ JWT
                                .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        // Xử lý khi xác thực thất bại bằng JwtAuthenticationEntryPoint (trả về lỗi JSON)
                        .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
        );

        // Tắt CSRF (Cross-Site Request Forgery) vì API thường không cần
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        // Xây dựng và trả về SecurityFilterChain đã cấu hình
        return httpSecurity.build();
    }

    /**
     * Định nghĩa bean JwtAuthenticationConverter để chuyển đổi thông tin xác thực từ JWT.
     * 
     * - JwtGrantedAuthoritiesConverter: Dùng để chuyển đổi các quyền (authorities) từ claim "scope" hoặc "authorities" trong JWT thành các GrantedAuthority của Spring Security.
     * - setAuthorityPrefix(""): Loại bỏ prefix mặc định "SCOPE_" khi chuyển đổi quyền, giúp quyền trong hệ thống không bị thêm tiền tố này.
     * - JwtAuthenticationConverter: Sử dụng JwtGrantedAuthoritiesConverter ở trên để chuyển đổi authorities từ JWT thành các GrantedAuthority.
     * 
     * @return JwtAuthenticationConverter đã được cấu hình
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        // Tạo converter để chuyển đổi quyền từ JWT, không thêm prefix "SCOPE_"
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        // Tạo JwtAuthenticationConverter và thiết lập converter cho authorities
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        // Trả về bean đã cấu hình
        return jwtAuthenticationConverter;
    }

    // đã sử dụng custom jwt decoder thay thế cho bean này
    // @Bean
    // JwtDecoder jwtDecoder(){
    //     SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
    //     return NimbusJwtDecoder
    //             .withSecretKey(secretKeySpec)
    //             .macAlgorithm(MacAlgorithm.HS512)
    //             .build();
    // }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }
}
