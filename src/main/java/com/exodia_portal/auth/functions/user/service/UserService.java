package com.exodia_portal.auth.functions.user.service;

import com.exodia_portal.auth.functions.user.dto.UserResponseDto;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    /**
     * Retrieves the currently logged-in user.
     *
     * @return UserResponseDto containing user details
     */
    UserResponseDto getLoggedInUser();
}
