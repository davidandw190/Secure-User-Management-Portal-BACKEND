package com.usersupportportal.service;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;

public interface EmailService {
    void sendNewPasswordEmail(String firstName, String password, String email) throws MessagingException;

    Message createEmail(String firstName, String password, String email) throws MessagingException;

    Session getEmailSession();
}
