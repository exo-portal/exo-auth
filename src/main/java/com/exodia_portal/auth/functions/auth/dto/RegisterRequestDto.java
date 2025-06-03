package com.exodia_portal.auth.functions.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDate;

public record RegisterRequestDto(
        String firstName,
        String fullName,
        String lastName,
        String phoneNumber,
        String gender,
        @JsonFormat(pattern = "yyyy-MM-dd") LocalDate dateOfBirth,
        String email,
        String password,
        String address,
        String barangay,
        String city,
        String postalCode,
        String state,
        String country
) {}