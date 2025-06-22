package com.exodia_portal.auth.functions.passwordhistory.service;

import com.exodia_portal.common.model.User;

public interface PasswordHistoryService {

    /**
     * Saves the user's password history.
     *
     * @param user     the user whose password history is being saved
     * @param password the password to be saved in the history
     */
    void savePasswordHistory(User user, String password);

    /**
     * Checks if the provided password is in the user's password history.
     *
     * @param user     the user whose password history is being checked
     * @param password the password to check against the history
     * @return true if the password is found in the history, false otherwise
     */
    boolean isPasswordInHistory(User user, String password);
}
