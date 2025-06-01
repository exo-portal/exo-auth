package com.exodia_portal.auth.functions.auth.service;

import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public interface AuthService {

    ResponseEntity<String> validateEmail(String email);

    /**
     * Handles user logout by invalidating the session and clearing the JWT cookie.
     *
     * @param request  the HttpServletRequest object
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with a success message
     */
    ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response);

    /**
     * Handles user login by generating access and refresh tokens.
     *
     * @param request  the LoginRequestDto containing login credentials
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with the generated tokens
     */
    ResponseEntity<Map<String, String>> login(LoginRequestDto request, HttpServletResponse response);

    /**
     * Registers a new user and generates access and refresh tokens.
     *
     * @param request  the RegisterRequestDto containing user registration details
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with the generated tokens
     */
    ResponseEntity<Map<String, String>> register(RegisterRequestDto request, HttpServletResponse response);

}
