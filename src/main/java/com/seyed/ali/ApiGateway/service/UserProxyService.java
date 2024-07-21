package com.seyed.ali.ApiGateway.service;

import com.seyed.ali.ApiGateway.keycloak.util.KeycloakSecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * This service class is responsible for handling the user.
 * <p>
 * It extracts the email from the JWT token and then makes a POST request to the authentication service endpoint to handle the user.
 * <p>
 * The handling of the user involves saving the user's basic information in the database or caching it in Redis for performance optimization.
 * <br><br>
 * TODO: Implement caching of requests to further optimize performance.
 *
 * @author [Seyed Ali]
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserProxyService {

    private @Value("${microservice.authentication-service.endpoint-url}") String endpointUrl;
    private @Value("${microservice.authentication-service.url}") String baseUrl;

    private final WebClient.Builder webclientBuilder;
    private final KeycloakSecurityUtil keycloakSecurityUtil;

    /**
     * Performs the handle user operation by calling the {@code Authentication-Service}.
     *
     * @param jwt the JWT token containing the user's information
     * @return a Mono of Void
     */
    public Mono<Void> performHandleUser(Jwt jwt) {
        String user = this.keycloakSecurityUtil.extractEmail(jwt);
        log.trace("-----------------------------------------------");
        log.trace("Attempting to handle user: {{}}", user);
        log.debug("Making request to Authentication-Service. URL: {{}}", this.baseUrl + this.endpointUrl);
        log.debug("Request headers: {}", jwt.getHeaders());

        // TODO: Implement caching of requests to improve performance
        // Currently, each request is made to the `Authentication-Service` without caching, which can lead to performance issues.
        // In a future branch and issue, we will implement caching using Redis to store the user information.

        return this.webclientBuilder
                .baseUrl(this.baseUrl).build()
                .post().uri(this.endpointUrl)
                .header(AUTHORIZATION, "Bearer " + jwt.getTokenValue())
                .retrieve()
                .bodyToMono(Void.class)
                .onErrorResume(WebClientResponseException.ServiceUnavailable.class, e -> {
                    log.error("Service Unavailable error when calling user-service - {{}}", e.getMessage());
                    return Mono.error(e);
                })
                .doOnSuccess(unused -> log.trace("Successfully handled user: {{}}", user));
    }

}
