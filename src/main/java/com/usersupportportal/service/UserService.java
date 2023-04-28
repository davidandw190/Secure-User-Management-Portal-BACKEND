package com.usersupportportal.service;

import com.usersupportportal.domain.User;
import com.usersupportportal.exception.domain.EmailExistException;
import com.usersupportportal.exception.domain.UserNotFoundException;
import com.usersupportportal.exception.domain.UsernameExistException;

import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, EmailExistException, UsernameExistException;

    List<User> getUsers();
    User findUserByUsername(String username);

    User findUserByEmail(String email);
}
