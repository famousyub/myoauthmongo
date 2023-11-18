package com.microservice.springsecurityoauth2mongodb.controller;


import com.microservice.springsecurityoauth2mongodb.document.User;
import com.microservice.springsecurityoauth2mongodb.payload.MessageResponse;
import com.microservice.springsecurityoauth2mongodb.payload.UserRequest;
import com.microservice.springsecurityoauth2mongodb.repositories.UserRepository;
import com.sun.security.auth.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin("*")
public class UserController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;


    @PostMapping("/save")
    public ResponseEntity<?> createUser(UserRequest userRequest){

        User me =new User();

        if(userRepository.existsByEmail(userRequest.getEmail())){

            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));

        }
        if(userRepository.existsByUsername(userRequest.getUsername())){
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));

        }

        me.setEmail(userRequest.getEmail());
        me.setUsername(userRequest.getUsername());
        String pass = passwordEncoder.encode(userRequest.getPassword());
        me.setPassword(pass);

        me.setFirstName(userRequest.getUsername());
        me.setLastName(userRequest.getUsername());

        List<String> roles  = new ArrayList<>();
        roles.add("ROLE_USER");
        roles.add("Role_EDUCATION");
        roles.add("ROLE_STUDENT");

        userRepository.save(me);

        return ResponseEntity.ok().body(me);
    }
}
