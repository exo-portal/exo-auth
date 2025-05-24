package com.exodia_portal.auth.functions.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@Service
public interface AuthService {

    ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response);

    ResponseEntity<Map<String, String>> login();

}
