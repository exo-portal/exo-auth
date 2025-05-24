package com.exodia_portal.auth.functions.jwt.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public interface JwtService {

    ResponseEntity<Map<String, String>> refreshToken(Map<String, String> request);

    ResponseEntity<String> getToken(HttpServletRequest request);

    String generateToken(String subject, long expiration);
}
