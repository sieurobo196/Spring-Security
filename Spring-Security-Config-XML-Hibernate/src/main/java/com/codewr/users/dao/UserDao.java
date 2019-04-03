package com.codewr.users.dao;

import com.codewr.users.model.User;

public interface UserDao {

    User findByUserName(String username);

}
