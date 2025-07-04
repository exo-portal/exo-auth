package com.exodia_portal.auth.functions.auth.controller;

import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import com.exodia_portal.auth.functions.auth.service.AuthService;
import com.exodia_portal.auth.functions.jwt.service.JwtService;
import com.exodia_portal.common.dto.ApiResultModel;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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
     * Verifies the session by checking the validity of the JWT token.
     * <p>
     * This endpoint is used to verify if the current session is valid by checking
     * the JWT token in the request. It returns an ApiResultModel indicating the
     * result of the verification.
     *
     * @param request the HttpServletRequest object containing the JWT token
     * @return an ApiResultModel indicating whether the session is valid or not
     */
    @GetMapping("/verify-session")
    public ApiResultModel verifySession(HttpServletRequest request) {
        return authService.verifySession(request);
    }

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
     * <p>
     * This endpoint handles user registration by accepting a request body
     * containing user details and returning an ApiResultModel with the generated tokens.
     *
     * @param request  the RegisterRequestDto containing user registration details
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the registration result and tokens
     */
    @PostMapping("/register")
    public ApiResultModel register(@RequestBody RegisterRequestDto request, HttpServletResponse response) {
        return authService.register(request, response);
    }

    /**
     * Handles user login by generating access and refresh tokens.
     * <p>
     * This endpoint processes the login request by validating the user's credentials
     * and returning an ApiResultModel containing the generated tokens.
     *
     * @param request  the LoginRequestDto containing user login details such as email and password
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the login result and tokens
     */
    @PostMapping("/login")
    public ApiResultModel login(@RequestBody LoginRequestDto request, HttpServletResponse response) {
        return authService.login(request, response);
    }

    /**
     * Logs out the user by clearing authentication-related cookies, invalidating the session,
     * and clearing the security context.
     * <p>
     * This method performs the following actions:
     * <ul>
     *   <li>Clears the JWT and refresh token cookies by calling the `SetCookie` method with `isLogout` set to `true`.</li>
     *   <li>Invalidates the current HTTP session to ensure no session data is retained.</li>
     *   <li>Clears the Spring Security context to remove any authentication information.</li>
     * </ul>
     * <p>
     * Returns a success response indicating the user has been logged out.
     *
     * @param request  the `HttpServletRequest` object representing the current HTTP request
     * @param response the `HttpServletResponse` object used to modify cookies and headers
     * @return an `ApiResultModel` containing the logout result
     */
    @PostMapping("/logout")
    public ApiResultModel logout(HttpServletRequest request, HttpServletResponse response) {
        return authService.logout(request, response);
    }

    /**
     * Switches the user's role based on the provided role in the request body.
     * <p>
     * This endpoint allows users to switch their roles by providing a role in the request body.
     * It returns an ApiResultModel indicating the result of the role switch operation.
     *
     * @param requestBody the request body containing the role to switch to
     * @param request     the HttpServletRequest object
     * @param response    the HttpServletResponse object
     * @return an ApiResultModel indicating the result of the role switch operation
     */
    @PostMapping("/switch-role")
    public ApiResultModel switchRole(@RequestBody Map<String, String> requestBody, HttpServletRequest request, HttpServletResponse response) {
        String role = requestBody.get("role");
        return authService.switchRole(role, request, response);
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
