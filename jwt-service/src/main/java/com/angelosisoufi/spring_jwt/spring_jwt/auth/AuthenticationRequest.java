package com.angelosisoufi.spring_jwt.spring_jwt.auth;

import com.angelosisoufi.spring_jwt.spring_jwt.validation.ValidPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @ValidPassword
    private String password;
}