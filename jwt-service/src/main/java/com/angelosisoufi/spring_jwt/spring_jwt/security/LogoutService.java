package com.angelosisoufi.spring_jwt.spring_jwt.security;

import com.angelosisoufi.spring_jwt.spring_jwt.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // Try to extract JWT from cookie
        String jwt = CookieUtil.getCookieValue(request, "access_token").orElse(null);

        // Revoke token in DB if exists
        if (jwt != null) {
            tokenRepository.findByToken(jwt).ifPresent(token -> {
                token.setExpired(true);
                token.setRevoked(true);
                tokenRepository.save(token);
                log.info("Access token revoked successfully.");
            });
        }

        // Clear cookies (access + refresh)
        CookieUtil.deleteCookie(response, "access_token", "/api/");
        CookieUtil.deleteCookie(response, "refresh_token", "/api/auth/refresh-token");

        // Clear context
        SecurityContextHolder.clearContext();
        log.info("User logged out and cookies cleared.");
    }
}