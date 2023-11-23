package com.libs.springjwt.controller;


import com.libs.springjwt.auth.JwtUtils;
import com.libs.springjwt.models.LoginCredentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginCredentials loginModel){
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginModel.getUsername(), loginModel.getPassword());
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        String token = jwtUtils.generate(loginModel.getUsername());

        return ResponseEntity.ok(token);
    }


    @GetMapping("/access") // accessible whether authorized or not
    public ResponseEntity<String> simpleTest() {
        return ResponseEntity.ok("always accessible");
    }

    @GetMapping("/auth") // test if you are authorized
    public ResponseEntity<String> isAuthorized(){
        return ResponseEntity.ok("you are authorized");
    }

}
