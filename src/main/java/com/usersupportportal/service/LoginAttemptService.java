package com.usersupportportal.service;

import java.util.concurrent.ExecutionException;

public interface LoginAttemptService {
    void evictUserFromLoginAttemptCache(String username);

    void addUserToLoginAttemptCache(String username);

    boolean hasExceededMaxAttempts(String username);
}
