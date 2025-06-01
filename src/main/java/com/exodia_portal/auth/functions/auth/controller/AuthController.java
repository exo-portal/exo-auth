package com.exodia_portal.auth.functions.auth.controller;

import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import com.exodia_portal.auth.functions.auth.service.AuthService;
import com.exodia_portal.auth.functions.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/authentication")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtService jwtService;

    /**
     * Validates the email address by checking if it exists in the system.
     *
     * @param email the email address to validate
     * @return a ResponseEntity indicating whether the email is valid or not
     */
    @GetMapping("/validate-email")
    public ResponseEntity<String> validateEmail(@RequestParam String email) {
        return authService.validateEmail(email);
    }

    /**
     * Registers a new user and generates access and refresh tokens.
     *
     * @param request  the RegisterRequestDto containing user registration details
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with the generated tokens
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequestDto request, HttpServletResponse response) {
        return authService.register(request, response);
    }

    /**
     * Handles user login by generating access and refresh tokens.
     *
     * @return a ResponseEntity with the generated tokens
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequestDto request, HttpServletResponse response) {
        return authService.login(request, response);
    }

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

}
