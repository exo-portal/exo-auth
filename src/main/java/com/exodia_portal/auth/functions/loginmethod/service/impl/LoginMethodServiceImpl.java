package com.exodia_portal.auth.functions.loginmethod.service.impl;

import com.exodia_portal.auth.functions.loginmethod.repository.LoginMethodRepository;
import com.exodia_portal.auth.functions.loginmethod.service.LoginMethodService;
import com.exodia_portal.auth.functions.user.helper.UserHelper;
import com.exodia_portal.common.dto.ApiResultModel;
import com.exodia_portal.common.model.LoginMethod;
import com.exodia_portal.common.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class LoginMethodServiceImpl implements LoginMethodService {

    @Autowired
    private LoginMethodRepository loginMethodRepository;

    /**
     * Unbinds a login method from a user.
     *
     * @param providerId   The unique identifier for the provider (e.g., GitHub, Google).
     * @param providerName The name of the provider (e.g., "github", "google").
     * @param userId       The unique identifier of the user.
     * @return ApiResultModel containing the result of the unbinding operation.
     */
    public ApiResultModel unbind(String providerId, String providerName, Long userId) {
        LoginMethod loginMethod = loginMethodRepository.findByProviderIdAndProviderNameAndUserIdAndIsDeletedFalse(providerId, providerName, userId)
                .orElseThrow(() -> new RuntimeException("Login method not found"));
        loginMethod.setDeleted(true);
        loginMethod = loginMethodRepository.save(loginMethod);

        User user = loginMethod.getUser();
        user.getLoginMethods().removeIf(LoginMethod::isDeleted);

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("Unbind successful")
                .resultData(UserHelper.response(user))
                .build();
    }
}
