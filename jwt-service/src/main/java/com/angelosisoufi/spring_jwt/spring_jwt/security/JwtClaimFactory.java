package com.angelosisoufi.spring_jwt.spring_jwt.security;

import com.angelosisoufi.spring_jwt.spring_jwt.user.User;
import com.angelosisoufi.spring_jwt.spring_jwt.user.Permission;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtClaimFactory {

    public Map<String, Object> fromUser(User user) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("roles", List.of("ROLE_" + user.getRole().name()));
        claims.put("permissions", user.getRole().getPermissions()
                .stream()
                .map(Permission::getPermission)
                .toList());

        return claims;
    }
}