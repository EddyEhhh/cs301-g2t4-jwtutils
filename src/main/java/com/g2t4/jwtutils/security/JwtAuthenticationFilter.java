package com.g2t4.jwtutils.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;



@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwkUtil jwkUtil;

    @Autowired
    public JwtAuthenticationFilter(JwkUtil jwkUtil) {
        this.jwkUtil = jwkUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (WebUtils.getCookie(request, "access_token") == null || WebUtils.getCookie(request, "id_token") == null){
            filterChain.doFilter(request, response);
            return;
        }
        String token = WebUtils.getCookie(request, "access_token").getValue();
        String id_token = WebUtils.getCookie(request, "id_token").getValue();
        if (token != null && validateToken(token) && validateToken(id_token)) {
            Claims claims = getClaimsFromToken(token);
            if (claims != null) {
                // Set authentication in the context
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(claims);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                httpRequest.setAttribute("id", jwkUtil.getValueFromTokenPayload(id_token, "sub"));
                httpRequest.setAttribute("username", jwkUtil.getValueFromTokenPayload(id_token, "cognito:username"));
                httpRequest.setAttribute("email", jwkUtil.getValueFromTokenPayload(id_token, "email"));
                httpRequest.setAttribute("first_name", jwkUtil.getValueFromTokenPayload(id_token, "custom:first_name"));
                httpRequest.setAttribute("last_name", jwkUtil.getValueFromTokenPayload(id_token, "custom:last_name"));
                httpRequest.setAttribute("role", jwkUtil.getValueFromTokenPayload(id_token, "custom:role"));
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean validateToken(String token) {
        try {
            String kid = jwkUtil.getKidFromTokenHeader(token);
            RSAPublicKey publicKey = jwkUtil.getPublicKey(kid);
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            logger.info(e.toString());
            return false;
        }
    }

    private Claims getClaimsFromToken(String token) {
        try {
            String kid = jwkUtil.getKidFromTokenHeader(token);
            RSAPublicKey publicKey = jwkUtil.getPublicKey(kid);
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            return null;
        }
    }
}
