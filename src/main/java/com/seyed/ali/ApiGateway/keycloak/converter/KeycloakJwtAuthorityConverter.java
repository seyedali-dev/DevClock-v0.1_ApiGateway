package com.seyed.ali.ApiGateway.keycloak.converter;

import com.seyed.ali.ApiGateway.keycloak.util.KeycloakSecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;

@Component
@RequiredArgsConstructor
public class KeycloakJwtAuthorityConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final KeycloakSecurityUtil keycloakSecurityUtil;

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
//    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = this.keycloakSecurityUtil.extractAuthorities(jwt);
        return Mono.just(jwt)
                .map(this.keycloakSecurityUtil::extractAuthorities)
                .map(grantedAuthorities -> new JwtAuthenticationToken(jwt, grantedAuthorities));
//        return new JwtAuthenticationToken(jwt, authorities);
    }

}
