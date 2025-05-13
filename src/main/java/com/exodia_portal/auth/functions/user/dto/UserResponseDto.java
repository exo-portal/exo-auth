package com.exodia_portal.auth.functions.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseDto {

    private long id;

    private String login;

    private String userName;

    private String email;

    private String mobileNumber;

    private String fullName;

    private String avatarUrl;

    private String googleId;

    private String githubId;

    private String emailId;
}
