package com.supportportal.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.supportportal.constant.SecurityConstant.*;
import com.supportportal.domain.UserPrincipal;
import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

public class JWTTokenProvider {

    @Value("jwt.secret")            // kept in app properties for practice reasons. Definitely a big "DO NOT"
    private String secret;
    
    public String generateJwtToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(DAVID_SRL_RO)
                           .withAudience(DAVID_SRL_ADMINISTRATION)
                           .withIssuedAt(new Date())
                           .withSubject(userPrincipal.getUsername())
                           .withArrayClaim(AUTHORITIES, claims)
                           .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                .sign(HMAC512(secret.getBytes())));
    }



    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
    }
}
