package com.exodia_portal.auth.functions.otp.repository;

import com.exodia_portal.common.model.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {

    /**
     * Finds an OTP entry by email and OTP code.
     *
     * @param email the email address associated with the OTP
     * @param otpCode the OTP code to search for
     * @return an Optional containing the Otp entity if found, or empty if not found
     */
    Optional<Otp> findByEmailAndOtpCode(String email, String otpCode);

    /**
     * Deletes the OTP entry associated with the given email.
     *
     * @param email the email address for which the OTP entry should be deleted
     */
    void deleteByEmail(String email);
}
