package com.dib.uniba.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dib.uniba.services.JwtService;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JwtService jwtService;

    public UserController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("profile")
    public ResponseEntity<Map<String, Object>> getUserDetails(@RequestHeader("Authorization") String authorizationHeader) {
        try {
            // Rimuovi "Bearer " dal token
            String token = authorizationHeader.replace("Bearer ", "");
            
            // Decodifica il token e ottieni i dettagli
            Map<String, Object> userDetails = jwtService.extractAllClaims(token);

            return ResponseEntity.ok(userDetails);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Token non valido."));
        }
    }
}

