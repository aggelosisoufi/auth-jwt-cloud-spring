package com.angelosisoufi.spring_jwt.spring_jwt.exception;

public class EmailAlreadyTakenException extends RuntimeException {

    public EmailAlreadyTakenException(String message) {
        super(message);
    }
}
