package com.exodia_portal.auth.functions.auth.service;

import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import com.exodia_portal.common.dto.ApiResultModel;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public interface AuthService {

    /**
     * Validates the provided email address.
     *
     * @param email the email address to validate
     * @return a ResponseEntity with a message indicating whether the email is valid or not
     */
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
     * Authenticates a user and generates access and refresh tokens.
     *
     * @param request  the LoginRequestDto containing user login details
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the authentication result and tokens
     */
    ApiResultModel login(LoginRequestDto request, HttpServletResponse response);

    /**
     * Registers a new user and generates access and refresh tokens.
     *
     * @param request  the RegisterRequestDto containing user registration details
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the registration result and tokens
     */
    ApiResultModel register(RegisterRequestDto request, HttpServletResponse response);

}
