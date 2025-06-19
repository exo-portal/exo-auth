package com.exodia_portal.auth.functions.forgotpassword.service.impl;

import com.exodia_portal.auth.functions.forgotpassword.service.ForgotPasswordService;
import com.exodia_portal.auth.functions.otp.service.OtpService;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.common.dto.ApiResultModel;
import com.exodia_portal.common.enums.ExoErrorKeyEnum;
import com.exodia_portal.common.enums.ExoErrorTypeEnum;
import com.exodia_portal.common.exceptions.ExoPortalException;
import com.exodia_portal.common.model.User;
import com.exodia_portal.common.utils.ExoErrorUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ForgotPasswordServiceImpl implements ForgotPasswordService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OtpService otpService;

    /**
     * Verifies the email address for password reset.
     * <p>
     * This method checks if the provided email address is registered in the system
     * and returns an ApiResultModel indicating whether the email is valid for password reset.
     *
     * @param email the email address to verify
     * @return an ApiResultModel indicating whether the email is valid for password reset
     */
    @Override
    public ApiResultModel verifyEmail(String email) {
        User user = userRepository.findByEmailAndIsDeletedFalse(email).orElseThrow(() -> new ExoPortalException(
                HttpStatus.NOT_FOUND.value(),
                ExoErrorTypeEnum.FIELD,
                List.of(ExoErrorUtil.buildFieldError("identifier", ExoErrorKeyEnum.USER_NOT_FOUND))
        ));

        // generate and send OTP
        otpService.generateAndSendOtp(user.getEmail());

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("Email verification successful")
                .build();
    }
}
