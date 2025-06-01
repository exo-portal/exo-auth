package com.exodia_portal.auth.filter;

import com.exodia_portal.auth.config.SecurityConfig;
import com.exodia_portal.common.constant.ExoConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String servletPath = request.getServletPath();
        boolean isPublicEndpoint = Arrays.stream(SecurityConfig.PUBLIC_ENDPOINTS)
                .anyMatch(endpoint -> new AntPathMatcher().match(endpoint, servletPath));
        System.out.println("Servlet Path: " + servletPath + ", Is Public Endpoint: " + isPublicEndpoint);
        return isPublicEndpoint;
    }
    /**
     * This method is called for each request to check if a JWT token is present in the cookies.
     * If a valid token is found, it sets the authentication in the SecurityContext.
     *
     * @param request     the HttpServletRequest object
     * @param response    the HttpServletResponse object
     * @param filterChain the FilterChain object
     * @throws ServletException if a servlet error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwt = null;
        System.out.println("Processing request in JwtAuthenticationFilter: " + request.getServletPath());
        // Extract JWT from cookies
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
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(userId, null, List.of(() -> "ROLE_USER"));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
