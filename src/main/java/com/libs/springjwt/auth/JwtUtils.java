package com.libs.springjwt.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.time.Instant;

public class JwtUtils {
    String SECRET = "adshfj dsjkJKHS JKHDSAK $J%LH^Jl;kdsajf lskdjafdsjaf kjasd jfdsaj fsajdfjsdafjl;sakdjf Kj^SAD AK-47kd hsljkahdsk $jhads#kj @h";
    private final JWTVerifier verifier;
    // expiry time in seconds
    long expiry =  60 * 60;

    Algorithm algorithm;

    public JwtUtils(){
        algorithm = Algorithm.HMAC512(SECRET);
        verifier = JWT.require(algorithm).acceptLeeway(expiry).build();
    }

    public String extractUsername(DecodedJWT token){
        return token.getClaim("username").asString();
    }

    public String extractUsername(String token){
        return extractUsername(verifier.verify(token));
    }


    public boolean validate(String token){
        try{
            DecodedJWT decodedJWT = verifier.verify(token);
            return validate(decodedJWT);
        }
        catch (Exception e){
            return false;
        }
    }
    public boolean validate(DecodedJWT token){
        try{
            Instant iat = token.getClaim("iat").asInstant();
            return iat.isAfter(Instant.now().minusSeconds(expiry));
        }
        catch(Exception e){
            return false;
        }
    }
    public String generate(String username){
        return JWT.create().withIssuedAt(Instant.now()).withClaim("username", username).sign(algorithm);
    }




}
