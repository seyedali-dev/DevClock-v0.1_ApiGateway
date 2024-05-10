package com.seyed.ali.ApiGateway.keycloak.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class KeycloakSecurityUtil {

    private final ObjectMapper objectMapper;

    public Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if (realmAccess == null) return new ArrayList<>();
        List<String> keycloakRoles = this.objectMapper.convertValue(realmAccess.get("roles"), List.class);
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for (String keycloakRole : keycloakRoles)
//            grantedAuthorities.add(new SimpleGrantedAuthority(STR."ROLE_\{keycloakRole}"));
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + keycloakRole));

        return grantedAuthorities;
    }

    public String extractEmail(Jwt jwt) {
        return jwt.getClaim("email");
    }

    public Mono<Jwt> extractTokenFromSecurityContext() {
        return ReactiveSecurityContextHolder.getContext()
                .handle((securityContext, sink) -> {
                    Authentication authentication = securityContext.getAuthentication();
                    if (authentication instanceof JwtAuthenticationToken) {
                        JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
                        sink.next(jwtAuthentication.getToken());
                        return;
                    }
                    sink.error(new IllegalStateException("No JWT token found in security context"));
                });
    }

}
