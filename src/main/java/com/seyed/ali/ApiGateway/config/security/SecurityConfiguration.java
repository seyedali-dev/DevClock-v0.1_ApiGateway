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
    private final String[] authenticatedResources = {
            "/eureka/**",
            "/actuator/**",
            "/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/swagger-resources/**", "/webjars/**", "/aggregate/**", "/favicon.ico", "/authentication-service/v3/api-docs",
            "/h2-console/**"
    };

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(customizer -> customizer
                        .pathMatchers(this.authenticatedResources).permitAll()
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
