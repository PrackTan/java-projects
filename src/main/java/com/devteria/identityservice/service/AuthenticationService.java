package com.devteria.identityservice.service;

import com.devteria.identityservice.dto.request.AuthenticationRequest;
import com.devteria.identityservice.dto.request.IntrospectRequest;
import com.devteria.identityservice.dto.request.LogoutRequest;
import com.devteria.identityservice.dto.response.AuthenticationResponse;
import com.devteria.identityservice.dto.response.IntrospectResponse;
import com.devteria.identityservice.entity.InvalidatedToken;
import com.devteria.identityservice.entity.User;
import com.devteria.identityservice.exception.AppException;
import com.devteria.identityservice.exception.ErrorCode;
import com.devteria.identityservice.repository.InvalidatedTokenRepository;
import com.devteria.identityservice.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;

// AuthenticationService chịu trách nhiệm xử lý logic xác thực, sinh token, kiểm tra token, logout (vô hiệu hóa token) cho hệ thống.

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    // Repository thao tác với bảng User
    UserRepository userRepository;
    // Repository thao tác với bảng lưu các token đã bị vô hiệu hóa (logout)
    InvalidatedTokenRepository invalidatedTokenRepository;

    // Khóa bí mật dùng để ký và xác thực JWT, lấy từ file cấu hình
    @NonFinal
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;

    /**
     * Kiểm tra tính hợp lệ của token (introspect)
     * @param request chứa token cần kiểm tra
     * @return IntrospectResponse (valid: true/false)
     */
    public IntrospectResponse introspect(IntrospectRequest request)
            throws JOSEException, ParseException {
        var token = request.getToken();
        SignedJWT jwtToken = null;
        try {
            // Xác thực token (chữ ký, hạn dùng)
             jwtToken = verifyToken(token);
        } catch (AppException e) {
            return IntrospectResponse.builder()
                    .valid(false)
                    .build();
        }

        // Trả về valid = true nếu token còn hạn
        return IntrospectResponse.builder()
                .valid(jwtToken.getJWTClaimsSet().getExpirationTime().after(new Date()))
                .build();
    }

    /**
     * Xác thực thông tin đăng nhập, trả về token nếu thành công
     * @param request thông tin đăng nhập (username, password)
     * @return AuthenticationResponse (token, authenticated)
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        // Tạo password encoder để kiểm tra mật khẩu
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

        // Tìm user theo username, nếu không có thì báo lỗi
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // So sánh mật khẩu nhập vào với mật khẩu đã mã hóa trong DB
        boolean authenticated = passwordEncoder.matches(request.getPassword(),
                user.getPassword());

        // Nếu sai mật khẩu thì báo lỗi
        if (!authenticated)
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        // Sinh JWT token cho user
        var token = generateToken(user);

        // Trả về token và authenticated = true
        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

    /**
     * Sinh JWT token cho user
     * @param user user đã xác thực
     * @return chuỗi JWT token
     */
    private String generateToken(User user) {
        // Tạo header cho JWT (thuật toán HS512)
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        // Xây dựng payload (claims) cho JWT
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername()) // subject là username
                .issuer("devteria.com") // issuer là hệ thống phát hành
                .issueTime(new Date()) // thời gian phát hành
                .expirationTime(new Date(
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli() // hết hạn sau 1h
                ))
                .claim("scope", buildScope(user)) // scope: quyền của user
                .jwtID(UUID.randomUUID().toString()) // id duy nhất cho token
                .build();

        // Đóng gói claims vào payload
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        // Tạo đối tượng JWSObject (header + payload)
        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            // Ký token bằng khóa bí mật
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            // Trả về chuỗi token
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Xây dựng chuỗi scope (quyền) cho user, gồm ROLE_xxx và các permission
     * @param user user
     * @return chuỗi scope, ví dụ: "ROLE_ADMIN user.read user.write"
     */
    private String buildScope(User user){
        StringJoiner stringJoiner = new StringJoiner(" ");

        // Nếu user có roles thì duyệt từng role
        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                // Thêm tên role (ROLE_xxx)
                stringJoiner.add("ROLE_" + role.getName());
                // Nếu role có permission thì thêm từng permission
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions()
                            .forEach(permission -> stringJoiner.add(permission.getName()));
            });

        return stringJoiner.toString();
    }

    /**
     * Xử lý logout: lưu token vào bảng token đã bị vô hiệu hóa
     * @param logoutRequest chứa token cần logout
     */
    public void logout(LogoutRequest logoutRequest) throws ParseException, JOSEException{
        // Xác thực token
        var signedToken = verifyToken(logoutRequest.getToken());
        // Lấy JWT ID và thời gian hết hạn
        String jwtID = signedToken.getJWTClaimsSet().getJWTID();
        Date expiryTime = signedToken.getJWTClaimsSet().getExpirationTime();
        // Tạo đối tượng InvalidatedToken để lưu vào DB
        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .token(jwtID)
                .expiresTime(expiryTime)
                .build();
        invalidatedTokenRepository.save(invalidatedToken);
    }

    /**
     * Xác thực token: kiểm tra chữ ký, hạn dùng
     * @param token chuỗi JWT
     * @return SignedJWT đã xác thực
     * @throws ParseException, JOSEException nếu token không hợp lệ
     */
    private SignedJWT verifyToken(String token) throws ParseException, JOSEException{
        // Tạo verifier với khóa bí mật
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        // Parse token thành SignedJWT
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Lấy thời gian hết hạn
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        // Kiểm tra chữ ký và hạn dùng
        var verified = signedJWT.verify(verifier);
        if(!verified || expiryTime.before(new Date())){
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        if(invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID())){
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        return signedJWT;
    }
}
