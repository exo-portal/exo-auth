package com.exodia_portal.auth.functions.auth.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/authentication")
public class AuthController {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    /**
     * Handles user logout by invalidating the session and clearing the JWT cookie.
     *
     * @param request  the HttpServletRequest object
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with a success message
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear the JWT cookie
        Cookie jwtCookie = new Cookie("tkn", null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0); // Expire the cookie immediately
        response.addCookie(jwtCookie);

        // Invalidate the session
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();

        // Response message
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", "Logged out successfully");
        return ResponseEntity.ok(responseBody);
    }

    /**
     * Handles user login by generating access and refresh tokens.
     *
     * @return a ResponseEntity with the generated tokens
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            String email = oAuth2User.getAttribute("email");

            String accessToken = generateToken(email, accessTokenExpiration);
            String refreshToken = generateToken(email, refreshTokenExpiration);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);

            return ResponseEntity.ok(tokens);
        }
        return ResponseEntity.status(401).body(null);
    }

    /**
     * Refreshes the access token using the refresh token.
     *
     * @param request the request body containing the refresh token
     * @return a ResponseEntity with the new access token
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
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

    /**
     * Retrieves the security token from the request cookies.
     *
     * @param request the HttpServletRequest object
     * @return a ResponseEntity with the token or an error message
     */
    @GetMapping("/get-security-token")
    public ResponseEntity<String> getToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("tkn".equals(cookie.getName())) {
                    return ResponseEntity.ok(cookie.getValue());
                }
            }
        }
        return ResponseEntity.status(404).body("Token not found");
    }

    // TODO:: remove this method or move this in the jwt service
    /**
     * Generates a JWT token with the specified subject and expiration time.
     *
     * @param subject    the subject of the token
     * @param expiration the expiration time in milliseconds
     * @return the generated JWT token
     */
    private String generateToken(String subject, long expiration) {
        Key key = new javax.crypto.spec.SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

}
