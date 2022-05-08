package net.focik.zuulservice.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secret;
    public static final String AUTHORITIES = "authorities";
    public static final String GET_ARRAYS_LLC = "Progas";
    public static final String TOKEN_PREFIX = "Bearer ";

    public boolean isTokenValid(String token) {
        JWTVerifier verifier = getJwtVerifier();


        return !isTokenExpired(verifier, token);
    }

    public String getSubject(String token) {
        JWTVerifier verifier = getJwtVerifier();
        return verifier.verify(token).getSubject();
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    //zwraca role z tokena
    public String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJwtVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }


    private JWTVerifier getJwtVerifier() {
        JWTVerifier verifier;
        try {
            verifier = JWT.require(Algorithm.HMAC512(secret))
                    .withIssuer(GET_ARRAYS_LLC).build();
        } catch (JWTVerificationException ex) {
            //normalny ex log jako error
            throw new JWTVerificationException("Token cannot be verified");
        }

        return verifier;
    }

}
