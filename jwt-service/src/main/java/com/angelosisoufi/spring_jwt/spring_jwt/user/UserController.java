package com.angelosisoufi.spring_jwt.spring_jwt.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("hasRole('USER')")
public class UserController {

    @GetMapping
//    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<?> getUserDetails(Authentication auth) {
        String email = auth.getName(); // The username/email of the logged-in user
        Map<String, Object> info = Map.of("email", email);
        return ResponseEntity.ok(info);
    }
}