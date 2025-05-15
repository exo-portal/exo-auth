package com.exodia_portal.auth.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /**
     * This method is called when an authentication exception occurs.
     * It sends a 401 Unauthorized response with a JSON error message.
     *
     * @param request       the HttpServletRequest object
     * @param response      the HttpServletResponse object
     * @param authException the AuthenticationException that occurred
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Unauthorized\",\"isSuccess\": \"false\", \"message\": \"JWT token is missing or invalid\"}");
    }
}
