package com.dib.uniba.services;

import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.entities.User;
import com.dib.uniba.repositories.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service // Annota questa classe come un servizio gestito da Spring
public class AuthenticationService {
    
    private final UserRepository userRepository; // Repository per la gestione degli utenti nel database
    private final PasswordEncoder passwordEncoder; // Encoder delle password per sicurezza
    private final AuthenticationManager authenticationManager; // Gestore per l'autenticazione

    // Costruttore per l'iniezione delle dipendenze
    public AuthenticationService(
        UserRepository userRepository,
        AuthenticationManager authenticationManager,
        PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Registra un nuovo utente.
     * 
     * Questo metodo riceve un oggetto RegisterUserDto che contiene le informazioni dell'utente.
     * Crea un nuovo utente con il nome completo, email e password codificata,
     * quindi lo salva nel repository.
     *
     * @param input Dati dell'utente da registrare
     * @param string 
     * @return L'utente appena creato e salvato nel database
     */
    public User signup(RegisterUserDto input, String role) {
        User user = new User()
                .setFullName(input.getFullName()) // Imposta il nome completo dell'utente
                .setEmail(input.getEmail()) // Imposta l'email dell'utente
                .setPassword(passwordEncoder.encode(input.getPassword())) // Codifica e imposta la password
                .setRole(role); // Imposta il ruolo dell'utente

        return userRepository.save(user); // Salva l'utente nel database
    }

    /**
     * Autentica un utente.
     * 
     * Questo metodo autentica un utente sulla base delle credenziali di accesso ricevute.
     * Usa AuthenticationManager per verificare email e password, quindi recupera l'utente dal database.
     *
     * @param input Dati dell'utente per l'autenticazione
     * @return L'utente autenticato trovato nel database
     * @throws RuntimeException se l'utente non viene trovato
     */
    public User authenticate(LoginUserDto input) {
        try {
            // Esegue l'autenticazione usando email e password
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            input.getEmail(),
                            input.getPassword()
                    )
            );
        } catch (Exception e) {
            throw new UsernameNotFoundException("Credenziali non valide o utente non trovato.");
        }

        // Recupera l'utente dal database in base all'email
        return userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Utente non trovato."));
    }

}
