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

    /**
     * Verifies the OTP code for the given email.
     * If the OTP is valid and not expired, it returns a success message.
     * If the OTP is invalid or expired, it throws an exception.
     *
     * @param email   the email address associated with the OTP
     * @param otpCode the OTP code to verify
     * @return ApiResultModel indicating success or failure of the verification
     */
    ApiResultModel verifyOtp(String email, String otpCode) throws Exception;

    /**
     * Resends the OTP to the provided email address.
     *
     * @param email the email address to which the OTP should be resent
     * @return ApiResultModel indicating success or failure of the resend operation
     */
    ApiResultModel resendOtp(String email);
}
