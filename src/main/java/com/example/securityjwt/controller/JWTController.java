package com.example.securityjwt.controller;

import com.example.securityjwt.config.JWTUtil;
import com.example.securityjwt.config.MyAuthenticationManager;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Zhurenkov Pavel 31.03.2024
 */
@Controller
public class JWTController {
    @Value(value = "${app.stored.username}") String username;
    @Value(value = "${app.stored.authorities}") String authorities;
    @Value(value = "${app.stored.jwt}") String jwt;

    @Autowired
    JWTUtil jwtUtil;
    @Autowired
    MyAuthenticationManager myAuthenticationManager;

    @ResponseBody
    @RequestMapping("/GetJWT")
    public String getJWT(@RequestParam String enteredUsername, @RequestParam String enteredPassword){
        Authentication enteredAuth = new UsernamePasswordAuthenticationToken(enteredUsername, enteredPassword);
        Authentication returnedAuth = myAuthenticationManager.authenticate(enteredAuth);
        if (returnedAuth == null){
            return "User is Not Authenticated";
        }
        String username = (String) returnedAuth.getPrincipal();
        String authorities = (String) returnedAuth.getAuthorities().toString();

        String jwt = jwtUtil.createJWT(username, authorities);
        return jwt;
    }

    @ResponseBody
    @RequestMapping("/CreateJWT")
    public String createJWT(){
        return jwtUtil.createJWT(username, authorities);
    }

    @ResponseBody
    @RequestMapping("/DecodeJWT")
    public Claims decodeJWT(@RequestParam(required = false) String enteredJwt){
        if (enteredJwt == null) {
            Claims claims = jwtUtil.decodeJWT(jwt);
            return claims;
        } else {
            Claims claims = jwtUtil.decodeJWT(enteredJwt);
            return claims;
        }

    }
    @ResponseBody
    @RequestMapping("/GetUsername")
    public String getUsername(@RequestHeader("Authorization") String authorization){
        String jwt = jwtUtil.extractJWTFromAuthorizationHeader(authorization);
        return jwtUtil.getUsername(jwt);
    }
}
