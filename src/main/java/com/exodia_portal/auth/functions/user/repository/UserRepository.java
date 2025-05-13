package com.exodia_portal.auth.functions.user.repository;

import com.exodia_portal.common.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find a user by their login and check if they are not deleted.
     *
     * @param login the login of the user
     * @return an Optional containing the user if found and not deleted, or empty if not found or deleted
     */
    Optional<User> findByLoginAndIsDeletedFalse(String login);
}
