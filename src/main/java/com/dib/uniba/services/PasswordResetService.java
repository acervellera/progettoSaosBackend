package com.dib.uniba.services;

import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.dib.uniba.entities.PasswordResetToken;
import com.dib.uniba.entities.User;
import com.dib.uniba.repositories.PasswordResetTokenRepository;
import com.dib.uniba.repositories.UserRepository;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    // Costruttore con iniezione delle dipendenze
    public PasswordResetService(PasswordResetTokenRepository tokenRepository, UserRepository userRepository, EmailService emailService) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
    }

    /**
     * Genera un token di ripristino password per un utente dato l'email.
     * Invia un'email con il link di ripristino.
     *
     * @param email l'email dell'utente
     * @return il token generato
     */
    public String generateResetToken(String email) {
        // Verifica che l'utente esista
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email non trovata"));

        // Genera un token unico
        String token = UUID.randomUUID().toString();

        // Salva il token con una data di scadenza (es. 30 minuti)
        PasswordResetToken resetToken = new PasswordResetToken(
                token,
                email,
                LocalDateTime.now().plusMinutes(30)
        );
        tokenRepository.save(resetToken);

        // Invia l'email con il token
        String resetLink = "http://localhost:3000/reset-password?token=" + token;
        emailService.sendEmail(
                email,
                "Richiesta di Ripristino Password",
                "Clicca sul seguente link per ripristinare la tua password: " + resetLink
        );

        return token;
    }

    /**
     * Reimposta la password di un utente utilizzando un token valido.
     *
     * @param token il token di ripristino
     * @param newPassword la nuova password da impostare
     */
    public void resetPassword(String token, String newPassword) {
        // Trova il token
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Token non valido"));

        // Verifica se il token è scaduto
        if (resetToken.isExpired()) {
            throw new IllegalArgumentException("Token scaduto");
        }

        // Trova l'utente associato
        User user = userRepository.findByEmail(resetToken.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Utente non trovato"));

        // Aggiorna la password dell'utente
        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
        userRepository.save(user);

        // Rimuovi il token usato
        tokenRepository.delete(resetToken);
    }
}
