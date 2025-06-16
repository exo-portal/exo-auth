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
     * Verifies the user's session by checking the validity of the JWT token.
     * <p>
     * This method extracts the JWT token from the request, validates it, and determines
     * whether the user is authenticated. If the token is valid, the session is considered
     * active; otherwise, it returns an error response.
     *
     * @param request the HttpServletRequest object containing the user's session details
     * @return an ApiResultModel indicating the result of the session verification
     */
    ApiResultModel verifySession(HttpServletRequest request);

    /**
     * Validates the provided email address.
     *
     * @param email the email address to validate
     * @return a ResponseEntity with a message indicating whether the email is valid or not
     */
    ResponseEntity<String> validateEmail(String email);

    /**
     * Logs out the user by clearing authentication-related cookies, invalidating the session,
     * and clearing the security context.
     * <p>
     * This method ensures that the user's session is terminated securely by performing
     * the following actions:
     * <ul>
     *   <li>Clears the JWT and refresh token cookies.</li>
     *   <li>Invalidates the current HTTP session to remove session data.</li>
     *   <li>Clears the Spring Security context to remove authentication information.</li>
     * </ul>
     * <p>
     * Returns a success response indicating the logout operation was completed.
     *
     * @param request  the HttpServletRequest object representing the current HTTP request
     * @param response the HttpServletResponse object used to modify cookies and headers
     * @return an ApiResultModel containing the result of the logout operation
     */
    ApiResultModel logout(HttpServletRequest request, HttpServletResponse response);

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
