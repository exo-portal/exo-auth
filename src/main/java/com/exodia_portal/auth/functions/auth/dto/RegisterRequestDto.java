package com.exodia_portal.auth.functions.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequestDto {

    private String firstName;

    private String fullName;

    private String lastName;

    private String phoneNumber;

    private String gender;

    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;

    private String email;

    private String password;

    private String address;

    private String barangay;

    private String city;

    private String postalCode;

    private String state;

    private String country;

}
