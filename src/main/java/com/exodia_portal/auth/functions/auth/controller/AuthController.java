package com.exodia_portal.auth.functions.auth.controller;

import com.exodia_portal.auth.functions.auth.service.AuthService;
import com.exodia_portal.auth.functions.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/authentication")
public class AuthController {

    private AuthService authService;

    private JwtService jwtService;

    /**
     * Handles user logout by invalidating the session and clearing the JWT cookie.
     *
     * @param request  the HttpServletRequest object
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with a success message
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        return authService.logout(request, response);
    }

    /**
     * Handles user login by generating access and refresh tokens.
     *
     * @return a ResponseEntity with the generated tokens
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login() {
        return authService.login();
    }

    /**
     * Refreshes the access token using the refresh token.
     *
     * @param request the request body containing the refresh token
     * @return a ResponseEntity with the new access token
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        return jwtService.refreshToken(request);
    }

    /**
     * Retrieves the security token from the request cookies.
     *
     * @param request the HttpServletRequest object
     * @return a ResponseEntity with the token or an error message
     */
    @GetMapping("/get-security-token")
    public ResponseEntity<String> getToken(HttpServletRequest request) {
        return jwtService.getToken(request);
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
        return jwtService.generateToken(subject, expiration);
    }

}
