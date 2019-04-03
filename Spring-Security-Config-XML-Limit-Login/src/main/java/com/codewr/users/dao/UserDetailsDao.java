package com.codewr.users.dao;

import com.codewr.users.model.UserAttempts;

public interface UserDetailsDao {

    void updateFailAttempts(String username);

    void resetFailAttempts(String username);

    UserAttempts getUserAttempts(String username);

}
