package com.exodia_portal.auth.config;

import com.exodia_portal.auth.filter.CustomAuthenticationEntryPoint;
import com.exodia_portal.auth.filter.JwtAuthenticationFilter;
import com.exodia_portal.auth.functions.oauth.CustomOAuth2UserService;
import com.exodia_portal.common.constant.ExoConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Value("${allowed.origin}")
    private String allowedOrigins;

    public static final String[] PUBLIC_ENDPOINTS = {
            "/authentication/verify-session",
            "/authentication/logout",
            "/authentication/get-security-token",
            "/authentication/register",
            "/authentication/login",
            "/authentication/validate-email",
    };

    /**
     * Configures the security filter chain for the application.
     * This method sets up CORS, CSRF protection, and OAuth2 login.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                )
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        ).successHandler((request, response, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String jwtToken = (String) oAuth2User.getAttribute("jwtToken");

                            response.addHeader("Set-Cookie", ExoConstant.EXO_TOKEN_NAME + "=" + jwtToken + "; HttpOnly; Path=/; Secure; SameSite=Strict");
                            response.addHeader("Set-Cookie", ExoConstant.IS_LOGGED_IN + "=true; Path=/; Secure; SameSite=Strict");
                            response.sendRedirect("http://localhost:3000/auth/callback");
                        })
                );
        return http.build();
    }

    /**
     * CORS configuration to allow requests from the frontend application.
     * Adjust the allowed origins, methods, and headers as needed.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> origins = Arrays.asList(allowedOrigins.split(","));
        configuration.setAllowedOrigins(origins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Content-Type", "Authorization", "Cookie"));
        configuration.setExposedHeaders(List.of("Set-Cookie"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
