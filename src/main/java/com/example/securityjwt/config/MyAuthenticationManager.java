package com.example.securityjwt.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Zhurenkov Pavel 31.03.2024
 */
@Component
@Slf4j
public class MyAuthenticationManager implements AuthenticationManager {

    @Value(value = "${app.stored.username}")
    String storedUsername;
    @Value(value = "${app.stored.password}")
    String storedPassword;
    @Value(value = "${app.stored.authorities}")
    String storedAuthorities;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String enteredUsername = (String)authentication.getPrincipal();
        String enteredPassword = (String)authentication.getCredentials();

        if (!enteredUsername.equals(storedUsername)){
            log.error("Username not found");
            return null;
        }
        if (!enteredPassword.equals(storedPassword)){
            log.error("Incorrect Password");
            return null;
        }

        String[] authoritiesArray = storedAuthorities.split(", ");
        List<GrantedAuthority> authorities = new ArrayList<>();
        for(String authority: authoritiesArray){
            authorities.add(new SimpleGrantedAuthority(authority));
        }

        Authentication validateAuth = new UsernamePasswordAuthenticationToken(enteredUsername, null, authorities);

        return validateAuth;
    }
}
