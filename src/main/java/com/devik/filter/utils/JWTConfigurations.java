package com.devik.filter.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.devik.exceptions.JwtTokenNotFoundException;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Configuration
@Slf4j
public class JWTConfigurations {

    @Value("${jwt.secretkey}")
    public String jwt_secret_key;

    @Value("${jwt.token.title}")
    public String jwt_token_title;

    public Algorithm getJwtAlgorithm() {
        return Algorithm.HMAC256(jwt_secret_key);
    }

    public void creteJwtToken(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        LdapUserDetailsImpl userDetails= (LdapUserDetailsImpl) authentication.getPrincipal();

        String token = JWT.create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(getJwtAlgorithm());

        response.setHeader(jwt_token_title, token);
    }

    @SneakyThrows
    public void verify(HttpServletRequest request) {

        @NonNull String jwt_token = request.getHeader(jwt_token_title);

        if (jwt_token != null && jwt_token.startsWith("Bearer ")) {
            jwt_token = jwt_token.substring("Bearer ".length());

            JWTVerifier jwtVerifier = JWT.require(getJwtAlgorithm()).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(jwt_token);

            String username = decodedJWT.getSubject();
            Collection<SimpleGrantedAuthority> authorities = decodedJWT.getClaim("roles").asList(SimpleGrantedAuthority.class);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, authorities));
        }
        else
            throw new JwtTokenNotFoundException("Access token not provided");

    }

}
