package com.dib.uniba.controllers;

import org.springframework.web.bind.annotation.*;

import com.dib.uniba.services.PasswordResetService;

import org.springframework.http.ResponseEntity;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/request-password-reset")
    public ResponseEntity<String> requestPasswordReset(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        String token = passwordResetService.generateResetToken(email);

        // Simula l'invio dell'email (da implementare in futuro)
        System.out.println("Email inviata a " + email + " con token: " + token);

        return ResponseEntity.ok("Token di ripristino generato e inviato via email.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> requestBody) {
        String token = requestBody.get("token");
        String newPassword = requestBody.get("newPassword");

        passwordResetService.resetPassword(token, newPassword);
        return ResponseEntity.ok("Password aggiornata con successo.");
    }
}
