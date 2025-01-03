//package com.g2t4.jwtutils.security;
//
//import com.auth0.jwk.Jwk;
//import com.auth0.jwk.JwkProvider;
//import com.auth0.jwk.JwkProviderBuilder;
//import java.util.Base64;
//
//
//import jakarta.annotation.PostConstruct;
//import org.json.*;
//import java.security.interfaces.RSAPublicKey;
//import java.util.concurrent.TimeUnit;
//import org.springframework.stereotype.Component;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//
//@Service
//public class JwkUtil {
//
//    @Value("${cognito.userpool.id:not_found}")
//    private static String userPoolId;
//
//    private static String JWKS_URL = "https://cognito-idp.ap-southeast-1.amazonaws.com/" + userPoolId;
//
//    private static JwkProvider provider = new JwkProviderBuilder(JWKS_URL)
//                .cached(10, 24, TimeUnit.HOURS) // Cache up to 10 keys for 24 hours
//                .build();
//
//    public static RSAPublicKey getPublicKey(String kid) throws Exception {
//        Jwk jwk = provider.get(kid);
//        return (RSAPublicKey) jwk.getPublicKey();
//    }
//
//    public static String getKidFromTokenHeader(String token) {
//        String[] parts = token.split("\\.");
//        JSONObject header = new JSONObject(decode(parts[0]));
//        JSONObject payload = new JSONObject(decode(parts[1]));
//        String signature = decode(parts[2]);
//        return header.getString("kid");
//    }
//
//    private static String decode(String encodedString) {
//        return new String(Base64.getUrlDecoder().decode(encodedString));
//    }
//
//    public static String getValueFromTokenPayload(String token, String key) {
//        String[] parts = token.split("\\.");
//        JSONObject payload = new JSONObject(decode(parts[1]));
//        return payload.getString(key);
//    }
//
//}
