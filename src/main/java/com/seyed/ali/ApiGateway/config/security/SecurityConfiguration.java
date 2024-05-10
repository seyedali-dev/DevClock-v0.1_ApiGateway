package com.seyed.ali.ApiGateway.config.security;

import com.seyed.ali.ApiGateway.keycloak.converter.KeycloakJwtAuthorityConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final KeycloakJwtAuthorityConverter keycloakJwtAuthorityConverter;

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(customizer -> customizer
                        .pathMatchers("/eureka/**").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/swagger-ui/**", "/v3/api-docs/**", "/favicon.ico").permitAll()
                        .pathMatchers("/keycloak-user/verify-email/**").permitAll()
                        .pathMatchers("/h2-console/**").permitAll()
                        .anyExchange().authenticated()
                )
                .headers(headers -> headers.
                        frameOptions(ServerHttpSecurity.HeaderSpec.FrameOptionsSpec::disable)  // This is for H2 browser console access.
                )
                .oauth2ResourceServer(configurer -> configurer
                        .jwt(jwtConfigurer -> jwtConfigurer
                                .jwtAuthenticationConverter(this.keycloakJwtAuthorityConverter)
                        )
                )
        ;
        return httpSecurity.build();
    }

}
