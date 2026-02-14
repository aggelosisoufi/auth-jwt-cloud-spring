package com.angelosisoufi.spring_jwt.spring_jwt.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/csrf")
public class CsrfController {

    @GetMapping
    public ResponseEntity<Map<String, String>> csrfToken(CsrfToken token) {
        // Spring automatically injects CsrfToken argument
        return ResponseEntity.ok(Map.of(
                "token", token.getToken(),
                "headerName", token.getHeaderName(),
                "parameterName", token.getParameterName()
        ));
    }
}