package com.angelosisoufi.spring_jwt.spring_jwt.auth;

import com.angelosisoufi.spring_jwt.spring_jwt.model.SignUpRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(AuthApiPaths.BASE)
public class AuthController {
    private final AuthService service;

    public AuthController(AuthService service) {
        this.service = service;
    }

    @PostMapping(
            value = AuthApiPaths.SIGNIN,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthenticationRequest request, HttpServletResponse response) {
        service.authenticate(request, response);
        return ResponseEntity.ok(Map.of("message", "Login successful"));
    }

    @PostMapping(
            value = AuthApiPaths.SIGNUP,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest user) {
        service.register(user);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully. Please sign in."));
    }

    @PostMapping(value = AuthApiPaths.REFRESH_TOKEN, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        service.refreshToken(request, response);
        return ResponseEntity.ok(Map.of("message", "Access token refreshed successfully"));
    }
}
