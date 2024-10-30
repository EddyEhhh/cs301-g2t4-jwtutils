package com.g2t4.jwtutils.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtUtilConfig {

    @Bean
    public JwkUtil jwkUtil() {
        return new JwkUtil();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwkUtil jwkUtil) {
        return new JwtAuthenticationFilter(jwkUtil);
    }
}