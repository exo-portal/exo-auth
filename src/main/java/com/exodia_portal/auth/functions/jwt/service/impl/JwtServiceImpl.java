package com.exodia_portal.auth.functions.jwt.service.impl;

import com.exodia_portal.auth.functions.jwt.service.JwtService;
import com.exodia_portal.common.constant.ExoConstant;
import com.exodia_portal.common.enums.AccessLevelTypeEnum;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class JwtServiceImpl implements JwtService {

    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    public ResponseEntity<Map<String, String>> refreshToken(Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        try {
            String email = Jwts.parserBuilder()
                    .setSigningKey(new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName()))
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody()
                    .getSubject();
            String newAccessToken = generateToken(email, accessTokenExpiration);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", newAccessToken);

            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            return ResponseEntity.status(401).body(null);
        }
    }

    @Override
    public ResponseEntity<String> getToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ExoConstant.EXO_TOKEN_NAME.equals(cookie.getName())) {
                    return ResponseEntity.ok(cookie.getValue());
                }
            }
        }
        return ResponseEntity.status(404).body("Token not found");
    }

    /**
     * Generates a JWT token with the specified subject and expiration time.
     *
     * @param subject the subject of the token (usually the user's email or ID)
     * @param expiration the expiration time for the token in milliseconds
     * @return a JWT token as a String
     */
    @Override
    public String generateToken(String subject, long expiration) {
        Key key = new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generates a JWT token with roles and features included in the payload.
     *
     * @param subject the subject of the token (usually the user's email or ID)
     * @param currentRole the current role of the user
     * @param roles a list of roles assigned to the user
     * @param roleFeatureAccesses a list of features accessible by the user's roles
     * @param expiration the expiration time for the token in milliseconds
     * @return a JWT token as a String
     */
    @Override
    public String generateTokenWithRolesAndFeatures(String subject, AccessLevelTypeEnum currentRole, List<String> roles, List<String> roleFeatureAccesses, long expiration) {
        Key key = new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                .setSubject(subject)
                .claim("currentRole", currentRole)
                .claim("roles", roles)
                .claim("features", roleFeatureAccesses)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

}
