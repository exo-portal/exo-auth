package com.exodia_portal.auth.functions.passwordhistory.service.impl;

import com.exodia_portal.auth.functions.passwordhistory.repository.PasswordHistoryRepository;
import com.exodia_portal.auth.functions.passwordhistory.service.PasswordHistoryService;
import com.exodia_portal.common.model.PasswordHistory;
import com.exodia_portal.common.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PasswordHistoryServiceImpl implements PasswordHistoryService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordHistoryRepository passwordHistoryRepository;

    /**
     * Saves the old password to the user's password history.
     * This method is called when a user changes their password.
     *
     * @param user The user whose password history is being updated.
     * @param oldPassword The old password to be saved in the history.
     */
    @Override
    public void savePasswordHistory(User user, String oldPassword) {
        PasswordHistory passwordHistory = new PasswordHistory();
        passwordHistory.setUser(user);
        passwordHistory.setPassword(oldPassword);
        passwordHistoryRepository.save(passwordHistory);
    }

    /**
     * Checks if the provided password is in the user's password history.
     * This method checks the last 3 passwords stored in the history.
     *
     * @param user The user whose password history is being checked.
     * @param password The password to check against the history.
     * @return true if the password is found in the history, false otherwise.
     */
    @Override
    public boolean isPasswordInHistory(User user, String password) {
        // Fetch the last 5 password history entries for the user
        List<PasswordHistory> passwordHistories = passwordHistoryRepository.findByUserIdOrderByCreatedDateDesc(user.getId());

        // Check if the provided password matches any of the last 5 passwords
        return passwordHistories.stream()
                .limit(3) // Limit to the last 3 entries
                .anyMatch(history -> passwordEncoder.matches(password, history.getPassword()));
    }
}
