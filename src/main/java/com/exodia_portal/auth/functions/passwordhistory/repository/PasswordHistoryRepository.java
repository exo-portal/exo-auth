package com.exodia_portal.auth.functions.passwordhistory.repository;

import com.exodia_portal.common.model.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {

    /**
     * Finds the password history entries for a given user, ordered by creation date in descending order.
     *
     * @param userId the ID of the user whose password history is to be retrieved
     * @return a list of PasswordHistory entries for the specified user, ordered by created date
     */
    List<PasswordHistory> findByUserIdOrderByCreatedDateDesc(Long userId);
}
