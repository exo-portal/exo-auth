package com.exodia_portal.auth.functions.jwt.service;

import com.exodia_portal.common.enums.AccessLevelTypeEnum;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public interface JwtService {

    /** Refreshes the JWT token using the provided request map.
     *
     * @param request a map containing the refresh token
     * @return a ResponseEntity containing a map with the new access token, or an error response if the refresh fails
     */
    ResponseEntity<Map<String, String>> refreshToken(Map<String, String> request);

    /** Retrieves the JWT token from the request cookies.
     *
     * @param request the HTTP request containing cookies
     * @return a ResponseEntity containing the JWT token as a String, or an error response if not found
     */
    ResponseEntity<String> getToken(HttpServletRequest request);

    /** Generates a JWT token with the specified subject and expiration time.
     *
     * @param subject the subject of the token (usually the user ID or email)
     * @param expiration the expiration time for the token in milliseconds
     * @return a JWT token as a String
     */
    String generateToken(String subject, long expiration);

    /** Generates a JWT token with roles and features.
     *
     * @param subject the subject of the token (usually the user ID or email)
     * @param currentRole the current role of the user
     * @param roles a list of roles assigned to the user
     * @param roleFeatureAccesses a list of features accessible by the user's roles
     * @param expiration the expiration time for the token in milliseconds
     * @return a JWT token as a String
     */
    String generateTokenWithRolesAndFeatures(
            String subject,
            AccessLevelTypeEnum currentRole,
            List<String> roles,
            List<String> roleFeatureAccesses,
            long expiration
    );
}
