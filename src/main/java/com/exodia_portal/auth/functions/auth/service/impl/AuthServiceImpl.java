package com.exodia_portal.auth.functions.auth.service.impl;

import com.exodia_portal.auth.filter.JwtAuthenticationToken;
import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import com.exodia_portal.auth.functions.auth.service.AuthService;
import com.exodia_portal.auth.functions.jwt.service.JwtService;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.common.constant.ExoErrorKeyEnum;
import com.exodia_portal.common.constant.ExoErrorTypeEnum;
import com.exodia_portal.common.exceptions.ExoPortalException;
import com.exodia_portal.common.model.User;
import com.exodia_portal.common.utils.ExoErrorUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.exodia_portal.common.constant.ExoConstant.EXO_JSESSION_ID;
import static com.exodia_portal.common.constant.ExoConstant.EXO_REFRESH_TOKEN_NAME;
import static com.exodia_portal.common.constant.ExoConstant.EXO_TOKEN_NAME;
import static com.exodia_portal.common.constant.ExoConstant.IS_LOGGED_IN;

@Service
public class AuthServiceImpl implements AuthService {

    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Validates the provided email address by checking if it is already registered.
     *
     * @param email the email address to validate
     * @return a ResponseEntity with a message indicating whether the email is available for registration or not
     */
    @Override
    public ResponseEntity<String> validateEmail(String email) {
        // Check if the email is already registered
        boolean isEmailRegistered = userRepository.findByEmailAndIsDeletedFalse(email).isPresent();
        if (isEmailRegistered) {
            throw new ExoPortalException(
                    401,
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError(User.EMAIL, ExoErrorKeyEnum.EMAIL_ALREADY_EXISTS)
                    )
            );
        }
        return ResponseEntity.ok("Email is available for registration");
    }

    /**
     * Handles user logout by invalidating the session and clearing the JWT cookie.
     *
     * @param request  the HttpServletRequest object
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with a success message
     */
    @Override
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear the JWT and refresh token cookies
        SetCookie(null, null, response, true);

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
     * @param request  the login request containing email and password
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with the generated tokens
     */
    @Override
    public ResponseEntity<Map<String, String>> login(LoginRequestDto request, HttpServletResponse response) {
        // Authenticate user by email and password
        User user = userRepository.findByEmailAndIsDeletedFalse(request.getEmail())
                .filter(u -> passwordEncoder.matches(request.getPassword(), u.getPassword()))
                .orElse(null);

        if (user == null) {
            throw new ExoPortalException(
                    401,
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError(User.EMAIL, ExoErrorKeyEnum.INVALID_EMAIL_AND_PASSWORD),
                            ExoErrorUtil.buildFieldError(User.PASSWORD, ExoErrorKeyEnum.INVALID_EMAIL_AND_PASSWORD)
                    )
            );
        }

        // Generate tokens for the authenticated user
        String accessToken = jwtService.generateToken(String.valueOf(user.getId()), accessTokenExpiration);
        String refreshToken = jwtService.generateToken(String.valueOf(user.getId()), refreshTokenExpiration);

        SetCookie(accessToken, refreshToken, response);

        // Authenticate the user in the security context
        Authentication authentication = new JwtAuthenticationToken(user.getId(), null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Return success response
        return ResponseEntity.ok(Map.of("message", "Login successful"));
    }

    /**
     * Handles user registration by creating a new user and generating tokens.
     *
     * @param request  the registration request containing email, password, and full name
     * @param response the HttpServletResponse object
     * @return a ResponseEntity with a success message
     */
    @Override
    public ResponseEntity<Map<String, String>> register(RegisterRequestDto request, HttpServletResponse response) {
        if (userRepository.findByEmailAndIsDeletedFalse(request.getEmail()).isPresent()) {
            return ResponseEntity.status(400).body(Map.of("message", "User already exists"));
        }

        String login = request.getEmail().split("@")[0];

        User user = userRepository.findByLoginAndIsDeletedFalse(login)
                .orElseGet(() -> User.builder()
                        .email(request.getEmail())
                        .login(login)
                        .fullName(request.getFullName())
                        .isEmailLoginEnabled(true)
                        .build());

        if (user.getEmail() == null) {
            user.setEmail(request.getEmail());
        }

        if (user.getLogin() == null) {
            user.setLogin(login);
        }
        user.setEmailLoginEnabled(true);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user = userRepository.save(user);

        // Generate tokens for the new user
        String accessToken = jwtService.generateToken(String.valueOf(user.getId()), accessTokenExpiration);
        String refreshToken = jwtService.generateToken(String.valueOf(user.getId()), refreshTokenExpiration);

        SetCookie(accessToken, refreshToken, response);

        // Authenticate the user in the security context
        Authentication authentication = new JwtAuthenticationToken(user.getId(), null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Return success response
        return ResponseEntity.ok(Map.of("message", "Registration successful"));
    }

    /**
     * Sets the JWT and refresh token cookies in the response.
     *
     * @param accessToken  the access token to set in the cookie
     * @param refreshToken the refresh token to set in the cookie
     * @param response     the HttpServletResponse object
     */
    private void SetCookie(String accessToken, String refreshToken, HttpServletResponse response) {
        SetCookie(accessToken, refreshToken, response, false);
    }

    /**
     * Sets the JWT and refresh token cookies in the response, with an option to clear them.
     *
     * @param accessToken  the access token to set in the cookie
     * @param refreshToken the refresh token to set in the cookie
     * @param response     the HttpServletResponse object
     * @param isLogout     whether to clear the cookies (true) or set them (false)
     */
    private void SetCookie(String accessToken, String refreshToken, HttpServletResponse response, boolean isLogout) {
        if (!isLogout) {
            // Set Exo Token Cookie
            if (accessToken != null) {
                Cookie accessTokenCookie = new Cookie(EXO_TOKEN_NAME, accessToken);
                accessTokenCookie.setHttpOnly(true);
                accessTokenCookie.setPath("/");
                accessTokenCookie.setMaxAge((int) accessTokenExpiration / 1000);
                response.addCookie(accessTokenCookie);
            }

            // Set Exo Refresh Token Cookie
            if (refreshToken != null) {
                Cookie refreshTokenCookie = new Cookie(EXO_REFRESH_TOKEN_NAME, refreshToken);
                refreshTokenCookie.setHttpOnly(true);
                refreshTokenCookie.setPath("/");
                refreshTokenCookie.setMaxAge((int) refreshTokenExpiration / 1000);
                response.addCookie(refreshTokenCookie);
            }

            // Set isLoggedIn cookie
            Cookie isLoggedInCookies = new Cookie(IS_LOGGED_IN, "true");
            isLoggedInCookies.setHttpOnly(true);
            isLoggedInCookies.setPath("/");
            isLoggedInCookies.setMaxAge((int) refreshTokenExpiration / 1000);
            response.addCookie(isLoggedInCookies);
        } else {
            // Clear the JSESSIONID cookie
            Cookie jsessionCookie = new Cookie(EXO_JSESSION_ID, null);
            jsessionCookie.setHttpOnly(true);
            jsessionCookie.setSecure(true);
            jsessionCookie.setPath("/");
            jsessionCookie.setMaxAge(0);
            response.addCookie(jsessionCookie);

            // Clear the refresh token cookie
            Cookie refreshTokenCookie = new Cookie(EXO_REFRESH_TOKEN_NAME, null);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(0);
            response.addCookie(refreshTokenCookie);

            // Clear the JWT cookie
            Cookie jwtCookie = new Cookie(EXO_TOKEN_NAME, null);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(true);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(0);
            response.addCookie(jwtCookie);

            Cookie isLoggedInCookies = new Cookie(IS_LOGGED_IN, "false");
            isLoggedInCookies.setHttpOnly(true);
            isLoggedInCookies.setPath("/");
            isLoggedInCookies.setMaxAge(0);
            response.addCookie(isLoggedInCookies);
        }

    }

}