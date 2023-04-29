package com.usersupportportal.service.implementation;

import java.util.concurrent.ExecutionException;

public interface LoginAttemptService {
    void evictUserFromLoginAttemptCache(String username);

    void addUserToLoginAttemptCache(String username);

    boolean hasExceededMaxAttempts(String username) throws ExecutionException;
}
