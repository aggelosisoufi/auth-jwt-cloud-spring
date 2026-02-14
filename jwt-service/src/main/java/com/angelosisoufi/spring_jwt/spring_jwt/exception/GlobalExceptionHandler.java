package com.angelosisoufi.spring_jwt.spring_jwt.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * 🌐 Global Exception Handler
 *
 * Converts exceptions into RFC 9457-compliant Problem Details responses.
 * Logs errors for diagnostics without exposing sensitive info.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidationException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<Map<String, String>> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(this::toFieldError)
                .collect(Collectors.toList());

        log.warn("Validation error on {} -> {} fields invalid", request.getRequestURI(), errors.size());

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST,
                "Validation failed for one or more fields"
        );
        problem.setType(URI.create("https://example.com/problems/validation-error"));
        problem.setTitle("Validation Error");
        problem.setProperty("invalidFields", errors);
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ProblemDetail handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        List<String> violations = ex.getConstraintViolations()
                .stream()
                .map(ConstraintViolation::getMessage)
                .toList();

        log.warn("Constraint violation on {}: {}", request.getRequestURI(), violations);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Constraint violation");
        problem.setType(URI.create("https://example.com/problems/constraint-violation"));
        problem.setTitle("Constraint Violation");
        problem.setProperty("violations", violations);
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex, HttpServletRequest request) {
        log.warn("Bad credentials attempt at {}", request.getRequestURI());

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        problem.setType(URI.create("https://example.com/problems/bad-credentials"));
        problem.setTitle("Authentication Failed");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ProblemDetail handleUserNotFound(UsernameNotFoundException ex, HttpServletRequest request) {
        log.warn("User not found: {} (path: {})", ex.getMessage(), request.getRequestURI());

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setType(URI.create("https://example.com/problems/user-not-found"));
        problem.setTitle("User Not Found");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        log.warn("Access denied on {}", request.getRequestURI());

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Access is denied");
        problem.setType(URI.create("https://example.com/problems/access-denied"));
        problem.setTitle("Access Denied");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleDataIntegrity(DataIntegrityViolationException ex, HttpServletRequest request) {
        ex.getMostSpecificCause();
        String cause = ex.getMostSpecificCause().getMessage();
        log.error("Data integrity violation at {}: {}", request.getRequestURI(), cause);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Database constraint violated");
        problem.setType(URI.create("https://example.com/problems/data-integrity"));
        problem.setTitle("Data Integrity Violation");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setProperty("error", cause);
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler({
            ExpiredJwtException.class,
            MalformedJwtException.class,
            UnsupportedJwtException.class,
            SecurityException.class,
            IllegalArgumentException.class
    })
    public ProblemDetail handleJwtExceptions(Exception ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String detail;
        String type;

        if (ex instanceof ExpiredJwtException) {
            detail = "JWT token has expired";
            type = "https://example.com/problems/jwt-expired";
        } else if (ex instanceof MalformedJwtException) {
            detail = "JWT token is malformed";
            type = "https://example.com/problems/jwt-malformed";
        } else if (ex instanceof UnsupportedJwtException) {
            detail = "JWT token type is unsupported";
            type = "https://example.com/problems/jwt-unsupported";
        } else if (ex instanceof SecurityException) {
            detail = "JWT signature is invalid";
            type = "https://example.com/problems/jwt-invalid-signature";
        } else {
            detail = "Invalid or missing JWT token";
            type = "https://example.com/problems/jwt-invalid";
        }

        log.warn("JWT error on {}: {}", request.getRequestURI(), detail);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(type));
        problem.setTitle("JWT Authentication Error");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    @ExceptionHandler(InvalidCsrfTokenException.class)
    public ProblemDetail handleInvalidCsrf(InvalidCsrfTokenException ex, HttpServletRequest request) {
        // Try to retrieve the current CSRF token stored in request attributes
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String expected = token != null ? token.getToken() : "none";

        log.warn("""
          CSRF validation failed on path: {}
        - Expected token (from request): {}
        - Exception message: {}
        - Remote address: {}
        - Origin: {}
        - Referer: {}
        """,
                request.getRequestURI(),
                expected,
                ex.getMessage(),
                request.getRemoteAddr(),
                request.getHeader("Origin"),
                request.getHeader("Referer")
        );

        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Invalid CSRF token");
        pd.setType(URI.create("https://example.com/problems/csrf-invalid"));
        pd.setTitle("CSRF Validation Failed");
        pd.setProperty("timestamp", OffsetDateTime.now());
        pd.setInstance(URI.create(request.getRequestURI()));
        return pd;
    }

    @ExceptionHandler(RuntimeException.class)
    public ProblemDetail handleRuntimeException(RuntimeException ex, HttpServletRequest request) {
        log.error("Unhandled exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        problem.setType(URI.create("https://example.com/problems/internal-server-error"));
        problem.setTitle("Internal Server Error");
        problem.setProperty("timestamp", OffsetDateTime.now());
        problem.setProperty("error", ex.getMessage());
        problem.setInstance(URI.create(request.getRequestURI()));
        return problem;
    }

    private Map<String, String> toFieldError(FieldError fieldError) {
        return Map.of(
                "field", fieldError.getField(),
                "message", Objects.requireNonNull(fieldError.getDefaultMessage())
        );
    }
}
