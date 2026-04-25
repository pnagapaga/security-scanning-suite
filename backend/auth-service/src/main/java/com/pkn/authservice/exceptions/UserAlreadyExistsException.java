package com.pkn.authservice.exceptions;

public class UserAlreadyExistsException extends Exception{

    public UserAlreadyExistsException(String message) {
        super(message);
    }

}