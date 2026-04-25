package com.pkn.authservice.exceptions;

public class UserVerificationFailedException extends Exception{

    public UserVerificationFailedException(String message) {
        super(message);
    }
}
