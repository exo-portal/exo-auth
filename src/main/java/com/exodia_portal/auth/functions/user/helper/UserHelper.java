package com.exodia_portal.auth.functions.user.helper;

import com.exodia_portal.auth.functions.user.dto.UserResponseDto;
import com.exodia_portal.common.model.User;
import org.springframework.beans.BeanUtils;

public class UserHelper {

    /**
     * Converts a User entity to a UserResponseDto.
     *
     * @param user the User entity to convert
     * @return the converted UserResponseDto
     */
    public static UserResponseDto response(User user) {
        UserResponseDto response = new UserResponseDto();
        BeanUtils.copyProperties(user, response);

        user.getLoginMethods()
                .forEach(loginMethod -> {
                    if (loginMethod.getProviderName().equalsIgnoreCase("GOOGLE")) {
                        response.setGoogleId(loginMethod.getProviderId());
                    } else if (loginMethod.getProviderName().equalsIgnoreCase("GITHUB")) {
                        response.setGithubId(loginMethod.getProviderId());
                    }
                });

        if (user.getPassword() != null
                && !user.getPassword().isEmpty()
                && user.getEmail() != null
                && !user.getEmail().isEmpty()) {
            response.setEmailId(user.getEmail());
        }

        return response;
    }
}

