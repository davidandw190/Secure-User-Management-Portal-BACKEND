package com.usersupportportal.resource;

import com.usersupportportal.domain.User;
import com.usersupportportal.domain.UserPrincipal;
import com.usersupportportal.exception.ExceptionHandling;
import com.usersupportportal.exception.domain.EmailExistException;
import com.usersupportportal.exception.domain.UserNotFoundException;
import com.usersupportportal.exception.domain.UsernameExistException;
import com.usersupportportal.service.UserService;
import com.usersupportportal.utility.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.usersupportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping(path={"/", "/user"})
public class UserResource extends ExceptionHandling {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;

    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user)
            throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException {

        User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());

        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,      // We will do the conversion
                                           @RequestParam("isNonLocked") String isNonLocked, // to boolean in the backend
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
                            ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {

        User newUser = userService.addNewUser(firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isActive), profileImage);

        return new ResponseEntity<> (newUser, OK);

    }

    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam("currentUsername") String currentUsername,
                                           @RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,      // We will do the conversion
                                           @RequestParam("isNonLocked") String isNonLocked, // to boolean in the backend
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {

        User updatedUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isActive), profileImage);

        return new ResponseEntity<> (updatedUser, OK);

    }

    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username) {

        User foundUser = userService.findUserByUsername(username);

        return new ResponseEntity<>(foundUser, OK);

    }
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user)
            throws UserNotFoundException, EmailExistException, UsernameExistException {

        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);

        return new ResponseEntity<>(loginUser, OK);
    }


    private HttpHeaders getJwtHeader(UserPrincipal user) {

        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));

        return headers;
    }

    private void authenticate(String username, String password) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

    }



}



















