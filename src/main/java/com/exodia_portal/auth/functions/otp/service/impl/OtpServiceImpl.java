package com.exodia_portal.auth.functions.otp.service.impl;

import com.exodia_portal.auth.functions.otp.repository.OtpRepository;
import com.exodia_portal.auth.functions.otp.service.OtpService;
import com.exodia_portal.common.model.Otp;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class OtpServiceImpl implements OtpService {
    @Autowired
    private OtpRepository otpRepository;

    /**
     * Generates a 4-digit OTP for the given email and saves it to the database.
     * The OTP is valid for 10 minutes.
     *
     * @param email the email address to which the OTP will be sent
     */
    @Override
    @Transactional
    public void generateAndSendOtp(String email) {
        String otp = String.valueOf((int) (Math.random() * 9000) + 1000); // Generate 4-digit OTP
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(10); // Set expiration time

        otpRepository.deleteByEmail(email); // Remove any existing OTP for the email

        // Create a new OTP entity
        Otp otpEntity = Otp.builder()
                .email(email)
                .otpCode(otp)
                .expirationTime(expirationTime)
                .build();

        otpRepository.save(otpEntity); // Save the new OTP entity
    }
}
