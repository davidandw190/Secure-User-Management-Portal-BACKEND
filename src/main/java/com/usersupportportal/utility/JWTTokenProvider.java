package com.usersupportportal.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.usersupportportal.domain.UserPrincipal;

import static com.usersupportportal.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 *  Provides utilities to handle JSON Web Tokens (JWT) in the authentication
 *  process of the application. It contains methods to generate JWT tokens,
 *  extract user authorities from tokens, build authentication objects, and
 *  validate tokens.
 */
@Component
public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * Generates a JWT token for the provided user principal by setting claims
     * and signing the token using the application secret.
     */
    public String generateJwtToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create()
                .withIssuer(DAVID_SRL_RO)
                .withAudience(DAVID_SRL_ADMINISTRATION)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES, claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));
    }


    /**
     * Extracts the user authorities from the provided JWT token and returns them
     * as a list of GrantedAuthority objects.
     */
    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Builds and returns an Authentication object for the provided username, authorities, and HTTP request.
     */
    public static Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        var userPasswordAuthToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return userPasswordAuthToken;
    }

    /**
     * Validates the provided JWT token by verifying the token signature and expiration time
     * and comparing the username.
     */
    public boolean isTokenValid(String username, String token) {
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
    }

    /**
     * Extracts the subject from the provided JWT token.
     */
    public String getSubject(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }

    /**
     * Verifies if the provided JWT token is expired by extracting the expiration date from the token.
     */
    private boolean isTokenExpired(JWTVerifier verifier, String token ) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    //  Extracts and returns the user authorities from the provided JWT token.
    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    /**
     * Builds and returns a JWTVerifier object to verify JWT tokens.
     */
    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;

        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(DAVID_SRL_RO).build();
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }

        return verifier;
    }

    /**
     * Extracts and returns the user authorities from the UserPrincipal object.
     */
    private String[] getClaimsFromUser(UserPrincipal user) {
        List<String> authorities = new ArrayList<>();

        for (GrantedAuthority grantedAuthority : user.getAuthorities()) {
            authorities.add(grantedAuthority.getAuthority());
        }

        return authorities.toArray(new String[0]);
    }
}















































