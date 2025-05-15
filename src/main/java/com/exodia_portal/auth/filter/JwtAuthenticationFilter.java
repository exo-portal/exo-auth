package com.exodia_portal.auth.filter;

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
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String secretKey;

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

        // Extract JWT from cookies
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("tkn".equals(cookie.getName())) {
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
