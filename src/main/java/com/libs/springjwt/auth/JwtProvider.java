package com.libs.springjwt.auth;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Optional;

@Service
class JwtProvider implements AuthenticationProvider {

    @Autowired
    PasswordEncoder passwordEncoder;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();
        // get user information and check if it matches
        HashMap<String, String> usernamePasswordDatabase = new HashMap<>();
        usernamePasswordDatabase.put("omar", passwordEncoder.encode("password"));
        usernamePasswordDatabase.put("mona", passwordEncoder.encode("password"));
        usernamePasswordDatabase.put("ahmed", passwordEncoder.encode("password"));
        //
        if (!usernamePasswordDatabase.containsKey(username))
            return null;
        String actualPassword = usernamePasswordDatabase.get(username);
        // check for password here
        if (!passwordEncoder.matches(password, actualPassword))
            return null;

        return new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
