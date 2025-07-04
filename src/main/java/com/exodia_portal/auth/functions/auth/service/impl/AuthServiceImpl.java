package com.exodia_portal.auth.functions.auth.service.impl;

import com.exodia_portal.auth.filter.JwtAuthenticationToken;
import com.exodia_portal.auth.functions.auth.dto.LoginRequestDto;
import com.exodia_portal.auth.functions.auth.dto.LoginResponseDto;
import com.exodia_portal.auth.functions.auth.dto.RegisterRequestDto;
import com.exodia_portal.auth.functions.auth.service.AuthService;
import com.exodia_portal.auth.functions.jwt.service.JwtService;
import com.exodia_portal.auth.functions.user.helper.UserHelper;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.common.constant.ExoConstant;
import com.exodia_portal.common.dto.ApiResultModel;
import com.exodia_portal.common.enums.AccessLevelTypeEnum;
import com.exodia_portal.common.enums.ExoErrorKeyEnum;
import com.exodia_portal.common.enums.ExoErrorTypeEnum;
import com.exodia_portal.common.exceptions.ExoPortalException;
import com.exodia_portal.common.model.Role;
import com.exodia_portal.common.model.User;
import com.exodia_portal.common.model.UserInfo;
import com.exodia_portal.common.model.UserRole;
import com.exodia_portal.common.repository.RoleRepository;
import com.exodia_portal.common.utils.ExoErrorUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.exodia_portal.common.constant.ExoConstant.EXO_JSESSION_ID;
import static com.exodia_portal.common.constant.ExoConstant.EXO_REFRESH_TOKEN_NAME;
import static com.exodia_portal.common.constant.ExoConstant.EXO_TOKEN_NAME;
import static com.exodia_portal.common.constant.ExoConstant.IS_LOGGED_IN;

@Service
public class AuthServiceImpl implements AuthService {

    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;

    //noinspection FieldCanBeFinal
    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    @Value("${jwt.secret}")
    private String secretKey;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;

    /**
     * Verifies the user's session by checking the JWT token in the request cookies.
     * <p>
     * This method retrieves the JWT token from the request cookies, parses it to extract user details,
     * and checks if the user exists in the database. If the token is valid and the user is found,
     * it returns an ApiResultModel with user details. If the token is invalid or expired, it throws
     * an ExoPortalException with an appropriate error message.
     *
     * @param request the HttpServletRequest containing cookies with JWT token
     * @return an ApiResultModel containing user details if session is valid
     */
    @Override
    public ApiResultModel verifySession(HttpServletRequest request) {
        String jwt = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ExoConstant.EXO_TOKEN_NAME.equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }
        if (jwt != null) {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey.getBytes())
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                String userId = claims.getSubject();
                AccessLevelTypeEnum currentRole = AccessLevelTypeEnum.valueOf(claims.get("currentRole", String.class));
                List<String> roles = (List<String>) claims.get("roles", List.class);
                List<String> features = (List<String>) claims.get("features", List.class);

                User user = userRepository.findByIdAndIsDeletedFalse(Long.parseLong(userId))
                        .orElseThrow(() -> new ExoPortalException(
                                HttpStatus.UNAUTHORIZED.value(),
                                ExoErrorTypeEnum.MODAL,
                                List.of(ExoErrorUtil.buildFieldError("token", ExoErrorKeyEnum.INVALID_OR_EXPIRED_TOKEN))
                        ));

                LoginResponseDto userResponseDto = LoginResponseDto.builder()
                        .user(UserHelper.response(user))
                        .featureKeys(features)
                        .roleNames(roles)
                        .accessLevelRole(currentRole)
                        .build();

                if (SecurityContextHolder.getContext().getAuthentication() != null) {
                    return ApiResultModel.builder()
                            .isSuccess(true)
                            .message("User is Authorized")
                            .resultData(userResponseDto)
                            .build();
                }
            } catch (Exception e) {
                throw new ExoPortalException(
                        401,
                        ExoErrorTypeEnum.MODAL,
                        List.of(ExoErrorUtil.buildFieldError("token", ExoErrorKeyEnum.INVALID_OR_EXPIRED_TOKEN))
                );
            }
        }

        throw new ExoPortalException(
                401,
                ExoErrorTypeEnum.MODAL,
                List.of(ExoErrorUtil.buildFieldError("token", ExoErrorKeyEnum.INVALID_OR_EXPIRED_TOKEN))
        );
    }

    /**
     * Validates whether an email is available for registration.
     * <p>
     * This method checks if the provided email is already registered in the system.
     * If the email is found, it throws an `ExoPortalException` with HTTP status code 409
     * (Conflict) and an appropriate error message. Otherwise, it returns a success response
     * indicating the email is available for registration.
     *
     * @param email the email address to validate
     * @return a `ResponseEntity` containing a success message if the email is available
     * @throws ExoPortalException if the email is already registered
     */
    @Override
    public ResponseEntity<String> validateEmail(String email) {
        // Check if the email is already registered
        boolean isEmailRegistered = userRepository.findByEmailAndIsDeletedFalse(email).isPresent();
        if (isEmailRegistered) {
            throw new ExoPortalException(
                    409,
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError(User.USER_EMAIL_FIELD, ExoErrorKeyEnum.EMAIL_ALREADY_EXISTS)
                    )
            );
        }
        return ResponseEntity.ok("Email is available for registration");
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
    @Override
    public ApiResultModel logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear the JWT and refresh token cookies
        SetCookie(null, null, response, true);

        // Invalidate the session
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("Logged out successfully")
                .resultData(null)
                .build();
    }

    /**
     * Authenticates a user by validating their credentials and generates access and refresh tokens.
     * <p>
     * This method checks the provided email and password against the stored user data.
     * If the credentials are valid, it generates tokens and sets them in the response.
     * Otherwise, it throws an exception indicating invalid credentials.
     *
     * @param request  the LoginRequestDto containing the user's email and password
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the generated tokens and authentication result
     * @throws ExoPortalException if the email or password is invalid
     */
    @Override
    public ApiResultModel login(LoginRequestDto request, HttpServletResponse response) {
        // Validate the request parameters
        User user = userRepository.findByEmailAndIsDeletedFalse(request.getEmail())
                .filter(u -> passwordEncoder.matches(request.getPassword(), u.getPassword()))
                .orElse(null);

        // If user is not found or password does not match, throw an exception
        if (user == null) {
            throw new ExoPortalException(
                    401,
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError(User.USER_EMAIL_FIELD, ExoErrorKeyEnum.INVALID_EMAIL_AND_PASSWORD),
                            ExoErrorUtil.buildFieldError(User.USER_PASSWORD_FIELD, ExoErrorKeyEnum.INVALID_EMAIL_AND_PASSWORD)
                    )
            );
        }

        // Generate access and refresh tokens
        return generateAndSetTokens(user, response);
    }

    /**
     * Registers a new user and assigns a default role.
     * <p>
     * This method validates the user's email for uniqueness, creates a new user
     * with the provided registration details, assigns a default role, and saves
     * the user to the database. It also generates access and refresh tokens for
     * the newly registered user.
     *
     * @param request  the RegisterRequestDto containing user registration details
     * @param response the HttpServletResponse object used to set cookies or headers
     * @return an ApiResultModel containing the registration result and tokens
     * @throws ExoPortalException if the email is already registered or the role is not found
     */
    @Override
    public ApiResultModel register(RegisterRequestDto request, HttpServletResponse response) {
        if (userRepository.findByEmailAndIsDeletedFalse(request.email()).isPresent()) {
            throw new ExoPortalException(
                    400,
                    ExoErrorTypeEnum.TOAST,
                    List.of(
                            ExoErrorUtil.buildFieldError(User.USER_EMAIL_FIELD, ExoErrorKeyEnum.EMAIL_ALREADY_EXISTS)
                    )
            );
        }

        UserInfo userInfo = new UserInfo();
        BeanUtils.copyProperties(request, userInfo);
        userInfo.setFullName(request.firstName() + " " + request.lastName());

        String login = request.email().split("@")[0];
        User user = userRepository.findByLoginAndIsDeletedFalse(login)
                .orElseGet(() -> User.builder()
                        .login(login)
                        .email(request.email())
                        .password(passwordEncoder.encode(request.password()))
                        .isEmailLoginEnabled(true)
                        .build());

        if (user.getEmail() == null) {
            user.setEmail(request.email());
        }

        if (user.getLogin() == null) {
            user.setLogin(login);
        }

        // Assuming you have a Role object (e.g., fetched from the database or created)
        Role role = roleRepository.findByAccessLevelRole(AccessLevelTypeEnum.ROLE_SUPER_ADMIN)
                .orElseThrow(() -> new ExoPortalException(
                        404,
                        ExoErrorTypeEnum.TOAST,
                        List.of(ExoErrorUtil.buildFieldError("role", ExoErrorKeyEnum.ROLE_NOT_FOUND))
                ));

        UserRole userRole = UserRole.builder()
                .user(user)
                .role(role)
                .isDefaultRole(true) // Set as default role if needed
                .build();

        userInfo.setUser(user);
        user.setUserInfo(userInfo);

        if (user.getUserRoles() == null || user.getUserRoles().isEmpty()) {
            user.setUserRoles(List.of(userRole));
        } else {
            user.getUserRoles().add(userRole);
        }

        user = userRepository.save(user);

        return generateAndSetTokens(user, response);
    }

    /**
     * Switches the user's role based on the provided new role.
     * <p>
     * This method extracts the current JWT from cookies, validates it, and checks if the user
     * has the requested role. If valid, it generates new tokens with the selected role and updates
     * the security context. If the role is not allowed or does not exist, it throws an exception.
     *
     * @param newRole  the new role to switch to
     * @param request  the HttpServletRequest containing cookies with JWT token
     * @param response the HttpServletResponse used to set cookies or headers
     * @return an ApiResultModel containing the updated user details and tokens
     */
    @Override
    public ApiResultModel switchRole(String newRole, HttpServletRequest request, HttpServletResponse response) {
        // Validate the new role
        if (newRole == null || newRole.trim().isEmpty()) {
            throw new ExoPortalException(
                    400,
                    ExoErrorTypeEnum.TOAST,
                    List.of(ExoErrorUtil.buildFieldError("newRole", ExoErrorKeyEnum.INVALID_ROLE))
            );
        }

        // Extract the current JWT from cookies
        String jwt = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ExoConstant.EXO_TOKEN_NAME.equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        // If JWT is not found, throw an exception
        if (jwt == null) {
            throw new ExoPortalException(
                    401,
                    ExoErrorTypeEnum.MODAL,
                    List.of(ExoErrorUtil.buildFieldError("token", ExoErrorKeyEnum.INVALID_OR_EXPIRED_TOKEN))
            );
        }

        try {
            // Parse the JWT to extract user details
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey.getBytes())
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();

            String userId = claims.getSubject();
            List<String> roles = (List<String>) claims.get("roles", List.class);

            // Check if the requested role is valid and allowed
            if (!roles.contains(newRole)) {
                throw new ExoPortalException(
                        403,
                        ExoErrorTypeEnum.MODAL,
                        List.of(ExoErrorUtil.buildFieldError("role", ExoErrorKeyEnum.ROLE_NOT_ALLOWED))
                );
            }

            // Fetch the user from the database
            User user = userRepository.findByIdAndIsDeletedFalse(Long.parseLong(userId))
                    .orElseThrow(() -> new ExoPortalException(
                            HttpStatus.NOT_FOUND.value(),
                            ExoErrorTypeEnum.MODAL,
                            List.of(ExoErrorUtil.buildFieldError("user", ExoErrorKeyEnum.USER_NOT_FOUND))
                    ));

            // Check if the new role exists in the user's UserRole roles
            boolean roleExists = user.getUserRoles().stream()
                    .anyMatch(userRole -> userRole.getRole().getAccessLevelRole().name().equals(newRole));

            if (!roleExists) {
                throw new ExoPortalException(
                        HttpStatus.FORBIDDEN.value(),
                        ExoErrorTypeEnum.MODAL,
                        List.of(ExoErrorUtil.buildFieldError("role", ExoErrorKeyEnum.ROLE_NOT_EXIST))
                );
            }

            // Generate new tokens with the selected role
            AccessLevelTypeEnum accessLevelRole = AccessLevelTypeEnum.valueOf(newRole);
            List<String> featureKeys = user.getDefaultRoleFeatureKeys(); // Adjust if role-specific features are needed

            String accessToken = jwtService.generateTokenWithRolesAndFeatures(
                    String.valueOf(user.getId()),
                    accessLevelRole,
                    roles,
                    featureKeys,
                    accessTokenExpiration);

            String refreshToken = jwtService.generateTokenWithRolesAndFeatures(
                    String.valueOf(user.getId()),
                    accessLevelRole,
                    roles,
                    featureKeys,
                    refreshTokenExpiration);

            // Set the new tokens in cookies
            SetCookie(accessToken, refreshToken, response);

            // Update the security context
            Authentication authentication = new JwtAuthenticationToken(user.getId(), accessLevelRole, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Build the response
            LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                    .user(UserHelper.response(user))
                    .featureKeys(featureKeys)
                    .roleNames(roles)
                    .accessLevelRole(accessLevelRole)
                    .build();

            return ApiResultModel.builder()
                    .isSuccess(true)
                    .message("Role switched successfully")
                    .resultData(loginResponseDto)
                    .build();
        } catch (JwtException e) {
            throw new ExoPortalException(
                    HttpStatus.UNAUTHORIZED.value(),
                    ExoErrorTypeEnum.MODAL,
                    List.of(ExoErrorUtil.buildFieldError("token", ExoErrorKeyEnum.INVALID_OR_EXPIRED_TOKEN))
            );
        } catch (ExoPortalException e) {
            throw e;
        } catch (Exception e) {
            throw new ExoPortalException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    ExoErrorTypeEnum.MODAL,
                    List.of(ExoErrorUtil.buildFieldError("unexpected", ExoErrorKeyEnum.UNEXPECTED_ERROR))
            );
        }
    }

    /**
     * Generates access and refresh tokens for a user and sets them in the response.
     * <p>
     * This method retrieves the user's default access level role, feature keys, and role names.
     * It then generates access and refresh tokens using these details and sets them as cookies
     * in the HTTP response. Additionally, it authenticates the user in the security context.
     * Finally, it builds and returns an `ApiResultModel` containing the login response data.
     *
     * @param user     the `User` object containing user details
     * @param response the `HttpServletResponse` object used to set cookies
     * @return an `ApiResultModel` containing the login response data
     */
    private ApiResultModel generateAndSetTokens(User user, HttpServletResponse response) {
        AccessLevelTypeEnum accessLevelRole = user.getDefaultAccessLevelRole().orElse(AccessLevelTypeEnum.ROLE_APPLICANT); // Retrieve the default AccessLevelRole from the User
        List<String> featureKeys = user.getDefaultRoleFeatureKeys(); // Retrieve the feature keys from the default UserRole
        List<String> roleNames = user.getAccessLevelRoles().stream() // Retrieve all role names from the User's roles
                .map(AccessLevelTypeEnum::getAccessLevel) // Convert AccessLevelTypeEnum to String
                .toList();

        // Generate access and refresh tokens with roles and features
        String accessToken = jwtService.generateTokenWithRolesAndFeatures(
                String.valueOf(user.getId()),
                accessLevelRole,
                roleNames,
                featureKeys,
                accessTokenExpiration);

        String refreshToken = jwtService.generateTokenWithRolesAndFeatures(
                String.valueOf(user.getId()),
                accessLevelRole,
                roleNames,
                featureKeys,
                refreshTokenExpiration);

        // Set the cookies for access and refresh tokens
        SetCookie(accessToken, refreshToken, response);

        // Authenticate the user in the security context
        Authentication authentication = new JwtAuthenticationToken(user.getId(), accessLevelRole, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                .user(UserHelper.response(user))
                .featureKeys(featureKeys)
                .roleNames(roleNames)
                .accessLevelRole(accessLevelRole)
                .build();

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("Login successful")
                .resultData(loginResponseDto)
                .build();
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