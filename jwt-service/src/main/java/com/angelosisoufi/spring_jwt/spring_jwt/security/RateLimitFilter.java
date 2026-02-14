package com.angelosisoufi.spring_jwt.spring_jwt.security;

import com.angelosisoufi.spring_jwt.spring_jwt.auth.AuthApiPaths;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

@Component
@Order(1)
public class RateLimitFilter implements Filter {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Supplier<BucketConfiguration> signInBucketConfiguration;
    private final Supplier<BucketConfiguration> signUpBucketConfiguration;
    private final ProxyManager<String> proxyManager;

    public RateLimitFilter(
            @Qualifier("signInBucketConfiguration")
            Supplier<BucketConfiguration> signInBucketConfiguration,
            @Qualifier("signUpBucketConfiguration")
            Supplier<BucketConfiguration> signUpBucketConfiguration,
            ProxyManager<String> proxyManager
    ) {
        this.signInBucketConfiguration = signInBucketConfiguration;
        this.signUpBucketConfiguration = signUpBucketConfiguration;
        this.proxyManager = proxyManager;
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain filterChain
    ) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        String servletPath = httpRequest.getServletPath();
        if (!AuthApiPaths.SIGNIN_FULL.equals(servletPath) && !AuthApiPaths.SIGNUP_FULL.equals(servletPath)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        String clientIp = httpRequest.getRemoteAddr();
        String key;
        Supplier<BucketConfiguration> bucketConfiguration;
        if (AuthApiPaths.SIGNIN_FULL.equals(servletPath)) {
            key = "signin:" + clientIp;
            bucketConfiguration = signInBucketConfiguration;
        } else {
            key = "signup:" + clientIp;
            bucketConfiguration = signUpBucketConfiguration;
        }

        Bucket bucket = proxyManager.builder().build(key, bucketConfiguration);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        log.debug("Rate-limit remainingTokens for key {}: {}", key, probe.getRemainingTokens());
        if (probe.isConsumed()) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        httpResponse.setContentType(MediaType.TEXT_PLAIN_VALUE);
        httpResponse.setHeader(
                HttpHeaders.RETRY_AFTER,
                String.valueOf(TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()))
        );
        httpResponse.setStatus(429);
        httpResponse.getWriter().append("Too many requests");
    }
}
