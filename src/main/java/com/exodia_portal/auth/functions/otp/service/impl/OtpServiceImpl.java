package com.exodia_portal.auth.functions.otp.service.impl;

import com.exodia_portal.auth.functions.otp.repository.OtpRepository;
import com.exodia_portal.auth.functions.otp.service.OtpService;
import com.exodia_portal.common.dto.ApiResultModel;
import com.exodia_portal.common.enums.ExoErrorKeyEnum;
import com.exodia_portal.common.enums.ExoErrorTypeEnum;
import com.exodia_portal.common.exceptions.ExoPortalException;
import com.exodia_portal.common.model.Otp;
import com.exodia_portal.common.utils.ExoErrorUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;

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
        SecureRandom secureRandom = new SecureRandom();
        String otp = String.valueOf(secureRandom.nextInt(9000) + 1000); // Generate 4-digit OTP
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

    /**
     * Verifies the OTP code for the given email.
     * If the OTP is valid and not expired, it returns a success message.
     * If the OTP is invalid or expired, it throws an exception.
     *
     * @param email    the email address associated with the OTP
     * @param otpCode  the OTP code to verify
     * @return ApiResultModel indicating success or failure of the verification
     * @throws Exception if the OTP is invalid or expired
     */
    @Override
    @Transactional
    public ApiResultModel verifyOtp(String email, String otpCode) throws Exception {
        Otp otp = otpRepository.findByEmailAndOtpCode(email, otpCode).orElseThrow(() -> new ExoPortalException(
                HttpStatus.NOT_FOUND.value(),
                ExoErrorTypeEnum.FIELD,
                List.of(ExoErrorUtil.buildFieldError("pin", ExoErrorKeyEnum.OTP_INVALID))
        ));

        if (ObjectUtils.isEmpty(otp)) {
            return ApiResultModel.builder()
                    .isSuccess(false)
                    .message("Invalid OTP code")
                    .build();
        }

        otpRepository.deleteByEmail(email); // Remove any existing OTP for the email

        return ApiResultModel.builder()
                .isSuccess(true)
                .message("OTP verification successful")
                .build();
    }
}
