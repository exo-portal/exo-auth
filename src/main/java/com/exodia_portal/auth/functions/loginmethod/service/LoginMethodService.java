package com.exodia_portal.auth.functions.loginmethod.service;

import com.exodia_portal.common.dto.ApiResultModel;
import org.springframework.stereotype.Service;

@Service
public interface LoginMethodService {

    /**
     * Unbinds a login method from a user.
     *
     * @param providerId   The unique identifier for the provider (e.g., GitHub, Google).
     * @param providerName The name of the provider (e.g., "github", "google").
     * @param userId       The unique identifier of the user.
     * @return ApiResultModel containing the result of the unbinding operation.
     */
    ApiResultModel unbind(String providerId, String providerName, Long userId);

}
