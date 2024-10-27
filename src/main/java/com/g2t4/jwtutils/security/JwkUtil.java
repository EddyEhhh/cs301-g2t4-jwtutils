package com.g2t4.jwtutils.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwk.UrlJwkProvider;
import java.io.IOException;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

import org.json.*;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;


@Component
public class JwkUtil {

    private static String userPoolId;
    private static JwkProvider provider;

    @Value("${cognito.userpool.id}")
    public void setUserPoolId(String name) {
        userPoolId = name;
        initializeProvider();
    }

    private static void initializeProvider() {
        if (userPoolId != null) {
            String JWKS_URL = "https://cognito-idp.ap-southeast-1.amazonaws.com/" + userPoolId;
            provider = new JwkProviderBuilder(JWKS_URL)
                    .cached(10, 24, TimeUnit.HOURS) // Cache up to 10 keys for 24 hours
                    .build();
        } else {
            throw new IllegalStateException("UserPoolId is not set. Cannot initialize JwkProvider.");
        }
    }

    public static RSAPublicKey getPublicKey(String kid) throws Exception {
        Jwk jwk = provider.get(kid);
        return (RSAPublicKey) jwk.getPublicKey();
    }

    public static String getKidFromTokenHeader(String token) {
        String[] parts = token.split("\\.");
        JSONObject header = new JSONObject(decode(parts[0]));
        JSONObject payload = new JSONObject(decode(parts[1]));
        String signature = decode(parts[2]);
        return header.getString("kid");
    }

    private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

    public static String getValueFromTokenPayload(String token, String key) {
        String[] parts = token.split("\\.");
        JSONObject payload = new JSONObject(decode(parts[1]));
        return payload.getString(key);
    }

}
