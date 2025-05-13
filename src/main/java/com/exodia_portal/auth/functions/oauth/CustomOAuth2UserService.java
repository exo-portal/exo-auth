package com.exodia_portal.auth.functions.oauth;

import com.exodia_portal.auth.functions.loginmethod.repository.LoginMethodRepository;
import com.exodia_portal.auth.functions.user.repository.UserRepository;
import com.exodia_portal.common.model.LoginMethod;
import com.exodia_portal.common.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomOAuth2UserService implements OAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoginMethodRepository loginMethodRepository;

    /**
     * Loads the user information from the OAuth2 provider.
     *
     * @param userRequest The OAuth2 user request containing the client registration and access token.
     * @return An OAuth2User object containing the user's information.
     * @throws OAuth2AuthenticationException If an error occurs during authentication.
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        String providerName = userRequest.getClientRegistration().getRegistrationId();

        return switch (providerName) {
            case "google" -> googleAuthenticate(oAuth2User, providerName);
            case "github" -> githubAuthenticate(oAuth2User, providerName);
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + providerName);
        };
    }

    /**
     * Authenticates a user using Google OAuth2.
     *
     * @param oAuth2User The OAuth2 user object containing user information.
     * @param providerName The name of the provider (e.g., "google").
     * @return An OAuth2User object with the user's information.
     */
    private OAuth2User githubAuthenticate(OAuth2User oAuth2User, String providerName) {
        String providerId = oAuth2User.getName();
        String email = oAuth2User.getAttribute("email");
        String fullName = oAuth2User.getAttribute("name");
        String avatarUrl = oAuth2User.getAttribute("avatar_url");
        String login = oAuth2User.getAttribute("login");


        saveLoadUser(providerId, providerName, login, email, fullName, avatarUrl);

        return new DefaultOAuth2User(
                Collections.singleton(() -> "ROLE_USER"),
                oAuth2User.getAttributes(),
                "name"
        );
    }

    /**
     * Authenticates a user using Google OAuth2.
     *
     * @param oAuth2User The OAuth2 user object containing user information.
     * @param providerName The name of the provider (e.g., "google").
     * @return An OAuth2User object with the user's information.
     */
    private OAuth2User googleAuthenticate(OAuth2User oAuth2User, String providerName) {
        String providerId = oAuth2User.getName();
        String email = oAuth2User.getAttribute("email");
        String fullName = oAuth2User.getAttribute("name");
        String avatarUrl = oAuth2User.getAttribute("picture");
        String login = email.split("@")[0];

        saveLoadUser(providerId, providerName, login, email, fullName, avatarUrl);

        return new DefaultOAuth2User(
                Collections.singleton(() -> "ROLE_USER"),
                oAuth2User.getAttributes(),
                "name"
        );
    }

    /**
     * Saves or loads a user and their associated login method in the database.
     *
     * This method checks if a user with the given login exists and is not marked as deleted.
     * If the user does not exist, it creates a new user and saves it to the database.
     * It also checks if a login method associated with the given provider ID and provider name exists for the user.
     * If the login method does not exist, it creates a new one and saves it to the database.
     * If the login method is marked as deleted, it reactivates it by setting the deleted flag to false.
     *
     * @param providerId The unique identifier for the provider (e.g., GitHub, Google).
     * @param providerName The name of the provider (e.g., "github", "google").
     * @param login The login username or identifier for the user.
     * @param email The email address of the user.
     * @param fullName The full name of the user.
     * @param avatarUrl The URL of the user's avatar or profile picture.
     */
    private void saveLoadUser(String providerId, String providerName, String login, String email, String fullName, String avatarUrl) {
        User user = userRepository.findByLoginAndIsDeletedFalse(login)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .fullName(fullName)
                            .avatarUrl(avatarUrl)
                            .login(login)
                            .build();
                    return userRepository.save(newUser);
                });

        LoginMethod loginMethod = loginMethodRepository.findByProviderIdAndProviderNameAndUserId(
                providerId,
                providerName,
                user.getId()).orElseGet(() -> {
            LoginMethod newLoginMethod = LoginMethod.builder()
                    .providerId(providerId)
                    .providerName(providerName)
                    .user(user)
                    .build();
            return loginMethodRepository.save(newLoginMethod);
        });

        if (loginMethod.isDeleted()) {
            loginMethod.setDeleted(false);
            loginMethodRepository.save(loginMethod);
        }
    }
}
