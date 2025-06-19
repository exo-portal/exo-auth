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
}
