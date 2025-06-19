package com.exodia_portal.auth.functions.otp.service;

public interface OtpService {

    /**
     * Generates a 4-digit OTP for the given email and saves it to the database.
     * The OTP is valid for 10 minutes.
     *
     * @param email the email address to which the OTP will be sent
     */
    void generateAndSendOtp(String email);
}
