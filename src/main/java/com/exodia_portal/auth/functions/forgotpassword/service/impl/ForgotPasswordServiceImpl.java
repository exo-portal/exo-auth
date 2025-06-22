package com.exodia_portal.auth.functions.forgotpassword.service.impl;

import com.exodia_portal.auth.functions.forgotpassword.dto.UpdatePasswordRequestDto;
import com.exodia_portal.auth.functions.forgotpassword.service.ForgotPasswordService;
import com.exodia_portal.auth.functions.otp.service.OtpService;
import com.exodia_portal.auth.functions.passwordhistory.service.PasswordHistoryService;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.common.dto.ApiResultModel;
import com.exodia_portal.common.enums.ExoErrorKeyEnum;
import com.exodia_portal.common.enums.ExoErrorTypeEnum;
import com.exodia_portal.common.exceptions.ExoPortalException;
import com.exodia_portal.common.model.User;
import com.exodia_portal.common.utils.ExoErrorUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ForgotPasswordServiceImpl implements ForgotPasswordService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OtpService otpService;

    @Autowired
    private PasswordHistoryService passwordHistoryService;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

    /**
     * Verifies the OTP code for the given email.
     * If the OTP is valid and not expired, it returns a success message.
     * If the OTP is invalid or expired, it throws an exception.
     *
     * @param email   the email address associated with the OTP
     * @param otpCode the OTP code to verify
     * @return ApiResultModel indicating success or failure of the verification
     * @throws Exception if the OTP is invalid or expired
     */
    @Override
    public ApiResultModel verifyOtp(String email, String otpCode) throws Exception {
        return otpService.verifyOtp(email, otpCode);
    }

    /**
     * Resends the OTP to the provided email address.
     * <p>
     * This method generates a new OTP and sends it to the specified email address.
     *
     * @param email the email address to which the OTP should be resent
     * @return ApiResultModel indicating success of the operation
     */
    @Override
    public ApiResultModel resendOtp(String email) {
        otpService.generateAndSendOtp(email);

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("OTP has been resent to your email")
                .build();
    }

    /**
     * Resets the user's password.
     * <p>
     * This method checks if the email exists, verifies the new password against the old one,
     * and updates the user's password if all checks pass.
     *
     * @param request contains the email and new password
     * @return ApiResultModel indicating success or failure of the password reset
     */
    @Override
    public ApiResultModel resetPassword(UpdatePasswordRequestDto request) {
        // Check if the email exists in the system
        User user = userRepository.findByEmailAndIsDeletedFalse(request.email())
                .orElseThrow(() -> new ExoPortalException(
                        HttpStatus.NOT_FOUND.value(),
                        ExoErrorTypeEnum.TOAST,
                        List.of(ExoErrorUtil.buildFieldError("error", ExoErrorKeyEnum.USER_NOT_FOUND))
                ));

        // Check if the new password is the same as the previous password
        if (passwordEncoder.matches(request.newPassword(), user.getPassword())) {
            throw new ExoPortalException(
                    HttpStatus.BAD_REQUEST.value(),
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError("password", ExoErrorKeyEnum.PASSWORD_SAME_AS_PREVIOUS),
                            ExoErrorUtil.buildFieldError("confirmPassword", ExoErrorKeyEnum.PASSWORD_SAME_AS_PREVIOUS)
                    )
            );
        }

        // Check if the new password is the same as the old password
        if (passwordHistoryService.isPasswordInHistory(user, request.newPassword())) {
            throw new ExoPortalException(
                    HttpStatus.BAD_REQUEST.value(),
                    ExoErrorTypeEnum.FIELD,
                    List.of(
                            ExoErrorUtil.buildFieldError("password", ExoErrorKeyEnum.PASSWORD_SAME_AS_OLD),
                            ExoErrorUtil.buildFieldError("confirmPassword", ExoErrorKeyEnum.PASSWORD_SAME_AS_OLD)
                    )
            );
        }

        // Save the old password to history
        passwordHistoryService.savePasswordHistory(user, user.getPassword());

        // Update the user's password
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("Password reset successful")
                .build();
    }

}
