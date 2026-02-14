package com.angelosisoufi.spring_jwt.spring_jwt.auth;

import com.angelosisoufi.spring_jwt.spring_jwt.exception.EmailAlreadyTakenException;
import com.angelosisoufi.spring_jwt.spring_jwt.security.CookieUtil;
import com.angelosisoufi.spring_jwt.spring_jwt.security.JwtClaimFactory;
import com.angelosisoufi.spring_jwt.spring_jwt.security.JwtService;
import com.angelosisoufi.spring_jwt.spring_jwt.user.Role;
import com.angelosisoufi.spring_jwt.spring_jwt.user.User;
import com.angelosisoufi.spring_jwt.spring_jwt.model.SignUpRequest;
import com.angelosisoufi.spring_jwt.spring_jwt.user.UserRepository;
import com.angelosisoufi.spring_jwt.spring_jwt.token.Token;
import com.angelosisoufi.spring_jwt.spring_jwt.token.TokenRepository;
import com.angelosisoufi.spring_jwt.spring_jwt.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${jwt.expiration.refresh-token.expiration}")
    private long refreshExpirationMs;

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtClaimFactory jwtClaimFactory;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final TokenRepository tokenRepository;

    public void register(SignUpRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyTakenException("Email is already taken!");
        }

        User newUser = User.builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .password(encoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(newUser);
    }

    public void  authenticate(AuthenticationRequest request, HttpServletResponse response) {
        // Authenticate user credentials (email + password) against the configured AuthenticationProvider.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Email not found: " + request.getEmail()));

        String accessToken = jwtService.generateToken(jwtClaimFactory.fromUser(user), user);
        String refreshToken = jwtService.generateRefreshToken(user);

        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);

        setAuthCookies(response, accessToken, refreshToken);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = CookieUtil.getCookieValue(request, "refresh_token").orElse(null);
        if (refreshToken == null) {
            log.warn("No refresh token cookie found");
            return;
        }

        String userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail == null) {
            log.warn("Failed to extract user from refresh token");
            return;
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Email not found: " + userEmail));

        if (!jwtService.isTokenValid(refreshToken, user)) {
            log.warn("Invalid refresh token for user: {}", userEmail);
            return;
        }

        String newAccessToken = jwtService.generateToken(jwtClaimFactory.fromUser(user), user);

        revokeAllUserTokens(user);
        saveUserToken(user, newAccessToken);

        setAuthCookies(response, newAccessToken, refreshToken);
    }

    private void saveUserToken(User user, String jwtToken) {
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (!validUserTokens.isEmpty()) {
            validUserTokens.forEach(t -> {
                t.setExpired(true);
                t.setRevoked(true);
            });
            tokenRepository.saveAll(validUserTokens);
        }
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/")
                .maxAge(jwtExpirationMs / 1000)
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/auth/refresh-token")
                .maxAge(refreshExpirationMs / 1000)
                .build();

        CookieUtil.addCookie(response, accessCookie);
        CookieUtil.addCookie(response, refreshCookie);
    }

}
