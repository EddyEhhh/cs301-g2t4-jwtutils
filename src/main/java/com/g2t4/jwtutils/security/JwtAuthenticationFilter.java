package com.g2t4.jwtutils.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

    @Value("${cognito.userpool.id}")
    private String userPoolId;

    JwkProvider provider = new JwkProviderBuilder("https://cognito-idp.ap-southeast-1.amazonaws.com/" + userPoolId)
            .cached(10, 24, TimeUnit.HOURS) // Cache up to 10 keys for 24 hours
            .build();

    @PostConstruct
    public void init() {
        provider = createJwkProvider();
    }

    private JwkProvider createJwkProvider() {
        return new JwkProviderBuilder("https://cognito-idp.ap-southeast-1.amazonaws.com/" + userPoolId)
                .cached(10, 24, TimeUnit.HOURS)
                .build();
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        System.out.print("USERPOOL: " + userPoolId);
        if (WebUtils.getCookie(request, "access_token") == null || WebUtils.getCookie(request, "id_token") == null){
            filterChain.doFilter(request, response);
            return;
        }
        String token = WebUtils.getCookie(request, "access_token").getValue();
        String id_token = WebUtils.getCookie(request, "id_token").getValue();

        if (token != null && validateToken(token) && validateToken(id_token)) {
            Claims claims = getClaimsFromToken(token);
            String role = getValueFromTokenPayload(id_token, "custom:role");
            if (claims != null) {
                // Set authentication in the context
                List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));

                JwtAuthenticationToken authentication = new JwtAuthenticationToken(claims, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                httpRequest.setAttribute("id", getValueFromTokenPayload(id_token, "sub"));
                httpRequest.setAttribute("username", getValueFromTokenPayload(id_token, "cognito:username"));
                httpRequest.setAttribute("email", getValueFromTokenPayload(id_token, "email"));
                httpRequest.setAttribute("first_name", getValueFromTokenPayload(id_token, "custom:first_name"));
                httpRequest.setAttribute("last_name", getValueFromTokenPayload(id_token, "custom:last_name"));
                httpRequest.setAttribute("role", role);
            }

        }

        filterChain.doFilter(request, response);
    }

    private boolean validateToken(String token) {
        try {
            String kid = getKidFromTokenHeader(token);
            RSAPublicKey publicKey = getPublicKey(kid);
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
            String kid = getKidFromTokenHeader(token);
            RSAPublicKey publicKey = getPublicKey(kid);
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            return null;
        }
    }




    public RSAPublicKey getPublicKey(String kid) throws Exception {
        Jwk jwk = provider.get(kid);
        return (RSAPublicKey) jwk.getPublicKey();
    }

    public String getKidFromTokenHeader(String token) {
        String[] parts = token.split("\\.");
        JSONObject header = new JSONObject(decode(parts[0]));
        JSONObject payload = new JSONObject(decode(parts[1]));
        String signature = decode(parts[2]);
        return header.getString("kid");
    }

    private String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

    public String getValueFromTokenPayload(String token, String key) {
        String[] parts = token.split("\\.");
        JSONObject payload = new JSONObject(decode(parts[1]));
        return payload.getString(key);
    }

}
