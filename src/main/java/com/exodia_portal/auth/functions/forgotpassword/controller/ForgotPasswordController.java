package com.exodia_portal.auth.functions.forgotpassword.controller;

import com.exodia_portal.auth.functions.forgotpassword.service.ForgotPasswordService;
import com.exodia_portal.common.dto.ApiResultModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("forgot-password")
public class ForgotPasswordController {

    @Autowired
    private ForgotPasswordService forgotPasswordService;

    /**
     * Verifies the email address for password reset.
     * <p>
     * This endpoint checks if the provided email address is registered in the system
     * and returns an ApiResultModel indicating whether the email is valid for password reset.
     *
     * @param email the email address to verify
     * @return an ApiResultModel indicating whether the email is valid for password reset
     */
    @GetMapping("/verify-email")
    public ApiResultModel verifyEmail(@RequestParam String email) {
        return forgotPasswordService.verifyEmail(email);
    }

    /**
     * Resends the OTP to the provided email address.
     * <p>
     * This endpoint allows users to request a new OTP if they did not receive the original one.
     *
     * @param email the email address to which the OTP should be resent
     * @return ApiResultModel indicating success or failure of the resend operation
     */
    @GetMapping("/resend-otp")
    public ApiResultModel resendOtp(@RequestParam String email) {
        return forgotPasswordService.resendOtp(email);
    }

    /**
     * Verifies the OTP code for the given email.
     * <p>
     * This endpoint checks if the provided OTP code is valid and not expired for the specified email address.
     *
     * @param email   the email address associated with the OTP
     * @param otpCode the OTP code to verify
     * @return ApiResultModel indicating success or failure of the verification
     * @throws Exception if the OTP is invalid or expired
     */
    @GetMapping("/verify-otp")
    public ApiResultModel verifyOtp(@RequestParam String email, @RequestParam String otpCode) throws Exception {
        return forgotPasswordService.verifyOtp(email, otpCode);
    }


}
