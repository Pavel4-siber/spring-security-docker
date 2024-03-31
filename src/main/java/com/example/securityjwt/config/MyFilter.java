package com.example.securityjwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Zhurenkov Pavel 31.03.2024
 */
@Component
public class MyFilter implements Filter {

    @Autowired
    JWTUtil jwtUtil;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        String authorizationHeader = httpRequest.getHeader("Authorization");
        if (authorizationHeader != null){
            addAuthenticationObjectIntoContext(authorizationHeader);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private void addAuthenticationObjectIntoContext(String authorizationHeader) {
        String jwt = jwtUtil.extractJWTFromAuthorizationHeader(authorizationHeader);

        Claims claims = jwtUtil.getClaims(jwt);
        String username = (String)claims.get("username");
        String authoritiesJWT = (String)claims.get("authorities");

        String authString = authoritiesJWT.replace("[", "").replace("]", "").replace(" ", "");
        String[] authArray = authString.split(",");
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String authority: authArray){
            authorities.add(new SimpleGrantedAuthority(authority));
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
