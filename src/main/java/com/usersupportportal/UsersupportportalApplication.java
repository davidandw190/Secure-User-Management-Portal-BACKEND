package com.usersupportportal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;

import static com.usersupportportal.constant.FileConstant.USER_FOLDER;

@SpringBootApplication
public class UsersupportportalApplication {

    public static void main(String[] args) {
        SpringApplication.run(UsersupportportalApplication.class, args);
        new File(USER_FOLDER).mkdirs();
    }

}
