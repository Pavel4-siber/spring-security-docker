package com.example.securityjwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Zhurenkov Pavel 31.03.2024
 */
@Component
@Slf4j
public class JWTUtil {

    @Value(value = "${app.secret.key}")
    String SECRET_KEY;

    public String createJWT(String username, String authorities){

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        Map<String, Object> customerClaims = new HashMap<>();
        customerClaims.put("username", username);
        customerClaims.put("authorities", authorities);

        JwtBuilder builder = Jwts.builder()
                .setClaims(customerClaims)
                .setId("1")
                .setSubject("TestJWT")
                .setIssuer("ivoronline");

        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        String jwt = builder.signWith(signatureAlgorithm, signingKey).compact();

        return jwt;
    }

    public String extractJWTFromAuthorizationHeader(String authorization){
        if (authorization == null || !authorization.startsWith("Bearer ")){
            log.error("Authorization Header not found");
            return null;
        }
        String jwt = authorization.substring(7);

        return jwt;
    }

    public Claims getClaims(String jwt){
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                .parseClaimsJws(jwt)
                .getBody();
        return claims;
    }

    public String getUsername(String jwt){
        Claims claims = getClaims(jwt);
        String username = (String)claims.get("username");
        return username;
    }
    public Claims decodeJWT(String jwt){
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                .parseClaimsJws(jwt)
                .getBody();
        return claims;
    }
}
