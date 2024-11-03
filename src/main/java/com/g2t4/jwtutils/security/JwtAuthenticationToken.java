package com.g2t4.jwtutils.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Claims claims;

    public JwtAuthenticationToken(Claims claims, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.claims = claims;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return claims.getSubject();
    }

    public Claims getClaims() {
        return claims;
    }
}
