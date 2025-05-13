package com.exodia_portal.auth.functions.loginmethod.repository;

import com.exodia_portal.common.model.LoginMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginMethodRepository extends JpaRepository<LoginMethod, Long> {

    /**
     * Finds a login method by the provider ID, provider name, and user ID.
     *
     * This method retrieves an optional LoginMethod entity that matches the given
     * provider ID, provider name, and user ID. It is used to check if a specific
     * login method exists for a user in the database.
     *
     * @param providerId The unique identifier for the provider (e.g., GitHub, Google).
     * @param providerName The name of the provider (e.g., "github", "google").
     * @param userId The unique identifier of the user.
     * @return An Optional containing the LoginMethod if found, or an empty Optional if not.
     */
    Optional<LoginMethod> findByProviderIdAndProviderNameAndUserId(String providerId, String providerName, Long userId);

}
