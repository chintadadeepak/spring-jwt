package com.deepak.spring_security.controller;

import com.deepak.spring_security.models.Users;
import com.deepak.spring_security.service.JwtService;
import com.deepak.spring_security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;

@RestController
public class UserController {

    private JwtService jwtService;

    @Autowired
    public void setJwtService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    private UserService service;
    private AuthenticationManager manager;
    @Autowired
    public void setManager(AuthenticationManager manager) {
        this.manager = manager;
    }

    @Autowired
    public void setService(UserService service) {
        this.service = service;
    }
    @PostMapping("register")
    public Users registerUser(@RequestBody Users newUser) {
        return service.registerUser(newUser);
    }

    @PostMapping("login")
    public ResponseEntity<?> loginUser(@RequestBody Users loginUser) throws NoSuchAlgorithmException {
        Authentication authentication = manager.authenticate(
                new UsernamePasswordAuthenticationToken(loginUser.getUsername(),
                        loginUser.getPassword()));
        if(authentication.isAuthenticated())
            return new ResponseEntity<>(jwtService.generateToken(loginUser.getUsername()), HttpStatus.ACCEPTED);
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
