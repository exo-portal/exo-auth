package com.exodia_portal.auth.functions.user.service.impl;

import com.exodia_portal.auth.functions.user.dto.UserResponseDto;
import com.exodia_portal.auth.functions.user.helper.UserHelper;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.auth.functions.user.service.UserService;
import com.exodia_portal.common.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Retrieves the currently logged-in user.
     *
     * @return UserResponseDto containing user details
     */
    @Override
    public UserResponseDto getLoggedInUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            User user;
            Long id = (Long) oAuth2User.getAttribute("authId");
            String email = (String) oAuth2User.getAttribute("email");
            if (id != null) {
                enableIsDeletedFilter();
                user = userRepository.findByIdAndIsDeletedFalse(id).orElseThrow(() -> new RuntimeException("User not found"));
                return UserHelper.response(user);
            } else if (email != null) {
                enableIsDeletedFilter();
                user = userRepository.findByEmailAndIsDeletedFalse(email).orElseThrow(() -> new RuntimeException("User not found"));
                return UserHelper.response(user);
            }
        } else if (authentication != null && authentication.getPrincipal() instanceof org.springframework.security.core.userdetails.User userDetails) {
            // Handle email/password login
            return null;
        }

        return null;
    }

    /**
     * Enables the filter to exclude soft-deleted users from queries.
     */
    private void enableIsDeletedFilter() {
        entityManager.unwrap(org.hibernate.Session.class)
                .enableFilter("isDeletedFilter")
                .setParameter("isDeleted", false);
    }
}
