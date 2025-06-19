package com.exodia_portal.auth.functions.forgotpassword.service;

import com.exodia_portal.common.dto.ApiResultModel;
import org.springframework.stereotype.Service;

@Service
public interface ForgotPasswordService {

    /**
     * Verifies the email address for password reset.
     * <p>
     * This method checks if the provided email address is registered in the system
     * and returns an ApiResultModel indicating whether the email is valid for password reset.
     *
     * @param email the email address to verify
     * @return an ApiResultModel indicating whether the email is valid for password reset
     */
    ApiResultModel verifyEmail(String email);
}
