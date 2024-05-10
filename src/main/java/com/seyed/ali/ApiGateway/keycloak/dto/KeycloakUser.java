package com.seyed.ali.ApiGateway.keycloak.dto;

import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

public record KeycloakUser(String userId,
                           String firstName,
                           String lastName,
                           String username,
                           String email,
                           boolean emailVerified,
                           String phoneNumber,
                           String address,
                           String zoneInfo,
                           LocalDateTime birthDate) {
}
