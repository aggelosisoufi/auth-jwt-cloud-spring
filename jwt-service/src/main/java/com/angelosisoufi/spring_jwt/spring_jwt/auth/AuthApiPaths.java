package com.angelosisoufi.spring_jwt.spring_jwt.auth;

public final class AuthApiPaths {

    public static final String BASE = "/api/auth";
    public static final String SIGNIN = "/signin";
    public static final String SIGNUP = "/signup";
    public static final String REFRESH_TOKEN = "/refresh-token";

    public static final String SIGNIN_FULL = BASE + SIGNIN;
    public static final String SIGNUP_FULL = BASE + SIGNUP;

    private AuthApiPaths() {
    }
}
