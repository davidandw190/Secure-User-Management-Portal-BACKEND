package com.usersupportportal.resource;

import com.usersupportportal.domain.User;
import com.usersupportportal.exception.ExceptionHandling;
import com.usersupportportal.exception.domain.EmailExistException;
import com.usersupportportal.exception.domain.UserNotFoundException;
import com.usersupportportal.exception.domain.UsernameExistException;
import com.usersupportportal.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path={"/", "/user"})
public class UserResource extends ExceptionHandling {

    private final UserService userService;

    @Autowired
    public UserResource(UserService userService) {
        this.userService = userService;
    }


    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user)
            throws UserNotFoundException, EmailExistException, UsernameExistException {

        User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

}



















