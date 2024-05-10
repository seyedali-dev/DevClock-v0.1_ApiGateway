package com.seyed.ali.ApiGateway.config.security.interceptor;

import com.seyed.ali.ApiGateway.keycloak.util.KeycloakSecurityUtil;
import com.seyed.ali.ApiGateway.service.UserProxyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

/**
 * This class is a {@link WebFilter} that intercepts incoming requests and performs some actions
 * before forwarding the request to the next filter in the chain.
 * <p>
 * It is used to handle user management in a microservices' architecture.
 * <p>
 * Specifically, it intercepts each request, extracts the JWT token from the security context,
 * and then calls the {@link UserProxyService} to handle the user.
 * <p>
 * The handling of the user involves saving the user's basic information in the database and/or caching it in <strong>Redis</strong> for performance optimization.
 * <br><br>
 * TODO: Implement caching of requests to further optimize performance.
 *
 * @author [Seyed Ali]
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserInterceptor implements GlobalFilter, Ordered {

    // Client for the `Authentication-Service`, which is a microservice that provides user management functionality (both in keycloak & db).
    private final UserProxyService userProxyService;
    private final KeycloakSecurityUtil keycloakSecurityUtil;

    /**
     * The main entry point for the {@link WebFilter}.
     * <p>
     * <ol>
     *     <li> It is called for each incoming request.</li>
     *     <li> It retrieves the authentication information from the security context, and if it is a JWT token,
     *      it calls the Authentication-Service to handle the user.</li>
     *     <li> It then forwards the request to the next filter in the chain.</li>
     * </ol>
     *
     * @param exchange the ServerWebExchange object
     * @param chain    the GatewayFilterChain object
     * @return a Mono of Void
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Extract the JWT token from the security context
        return this.keycloakSecurityUtil.extractTokenFromSecurityContext()
                .flatMap(jwtToken ->
                        // Call the UserProxyService to handle the user
                        this.userProxyService.performHandleUser(jwtToken)
                                .then(chain.filter(exchange))
                ).onErrorResume(e -> {
                    log.error("Error processing user: {}", e.getMessage());
                    return Mono.error(e);
                });
    }

    /**
     * The order of the filter in the chain.
     *
     * @return the order of the filter
     */
    @Override
    public int getOrder() {
        return -1;
    }

}