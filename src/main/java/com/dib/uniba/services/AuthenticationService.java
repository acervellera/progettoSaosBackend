package com.dib.uniba.services;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.entities.User;
import com.dib.uniba.repositories.UserRepository;
import com.dib.uniba.utils.RoleEncryptionUtil;

@Service // Annota questa classe come un servizio gestito da Spring
public class AuthenticationService {
    
    private final UserRepository userRepository; // Repository per la gestione degli utenti nel database
    private final PasswordEncoder passwordEncoder; // Encoder delle password per sicurezza
    private final AuthenticationManager authenticationManager; // Gestore per l'autenticazione
    private final RoleEncryptionUtil roleEncryptionUtil; // Utilità per la crittografia del ruolo

    // Costruttore per l'iniezione delle dipendenze
    public AuthenticationService(
        UserRepository userRepository,
        AuthenticationManager authenticationManager,
        PasswordEncoder passwordEncoder,
        RoleEncryptionUtil roleEncryptionUtil
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleEncryptionUtil = roleEncryptionUtil;
    }

    /**
     * Registra un nuovo utente.
     * 
     * Questo metodo riceve un oggetto RegisterUserDto che contiene le informazioni dell'utente.
     * Crea un nuovo utente con il nome completo, email e password codificata,
     * quindi lo salva nel repository.
     *
     * @param input Dati dell'utente da registrare
     * @param role Ruolo dell'utente (USER o ADMIN)
     * @return L'utente appena creato e salvato nel database
     */
    public User signup(RegisterUserDto input, String role) {
        String encryptedRole;
        try {
            encryptedRole = roleEncryptionUtil.encryptRole(role); // Cripta il ruolo prima di salvarlo
        } catch (Exception e) {
            throw new RuntimeException("Errore nella crittografia del ruolo", e);
        }

        User user = new User()
                .setFullName(input.getFullName()) // Imposta il nome completo dell'utente
                .setEmail(input.getEmail()) // Imposta l'email dell'utente
                .setPassword(passwordEncoder.encode(input.getPassword())) // Codifica e imposta la password
                .setRole(encryptedRole); // Imposta il ruolo crittografato

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
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            input.getEmail(),
                            input.getPassword()
                    )
            );
        } catch (Exception e) {
            throw new UsernameNotFoundException("Credenziali non valide o utente non trovato.");
        }

        User user = userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Utente non trovato."));

        try {
            String decryptedRole = roleEncryptionUtil.decryptRole(user.getRole()); // Decripta il ruolo recuperato
            user.setRole(decryptedRole); // Imposta il ruolo decriptato
        } catch (Exception e) {
            throw new RuntimeException("Errore nella decrittografia del ruolo", e);
        }

        return user;
    }
}
