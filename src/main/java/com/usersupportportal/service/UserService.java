package com.usersupportportal.service;

import com.usersupportportal.domain.User;
import com.usersupportportal.exception.domain.EmailExistException;
import com.usersupportportal.exception.domain.EmailNotFoundException;
import com.usersupportportal.exception.domain.UserNotFoundException;
import com.usersupportportal.exception.domain.UsernameExistException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email)
            throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;

    List<User> getUsers();
    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked,
                    boolean isActive, MultipartFile profileImage)
            throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail,
                    String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage)
            throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;


    User updateProfileImage(String username, MultipartFile newProfileImage)
            throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    void deleteUser(long id);


}






















