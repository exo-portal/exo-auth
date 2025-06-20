package com.exodia_portal.auth.functions.otp.service;

import com.exodia_portal.common.dto.ApiResultModel;

public interface OtpService {

    /**
     * Generates a 4-digit OTP for the given email and saves it to the database.
     * The OTP is valid for 10 minutes.
     *
     * @param email the email address to which the OTP will be sent
     */
    void generateAndSendOtp(String email);

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
    ApiResultModel verifyOtp(String email, String otpCode) throws Exception;
}
