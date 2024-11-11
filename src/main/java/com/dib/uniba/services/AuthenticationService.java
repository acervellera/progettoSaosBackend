package com.dib.uniba.services;

import java.util.regex.Pattern;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.entities.User;
import com.dib.uniba.exception.InvalidArgumentCustomException;
import com.dib.uniba.exception.InvalidTokenException;
import com.dib.uniba.repositories.UserRepository;
import com.dib.uniba.utils.RoleEncryptionUtil;

@Service
public class AuthenticationService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RoleEncryptionUtil roleEncryptionUtil;

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
     * <p>
     * Nota: La password deve essere lunga almeno 8 caratteri.
     *
     * @param input Dati dell'utente da registrare
     * @param role Ruolo dell'utente (USER o ADMIN)
     * @return L'utente appena creato e salvato nel database
     * @throws InvalidArgumentCustomException se la password è inferiore a 8 caratteri
     */
    public User signup(RegisterUserDto input, String role) {
        // Verifica la lunghezza della password
        if (input.getPassword().length() < 8) {
            throw new InvalidArgumentCustomException("La password deve essere lunga almeno 8 caratteri.");
        }

        // Verifica il formato dell'email
        if (!isValidEmail(input.getEmail())) {
            throw new InvalidArgumentCustomException("Formato email non valido.");
        }

        // Verifica se l'email è già presente nel database
        if (userRepository.findByEmail(input.getEmail()).isPresent()) {
            throw new InvalidArgumentCustomException("Email già esistente. Scegli un'altra email.");
        }

        String encryptedRole;
        try {
            encryptedRole = roleEncryptionUtil.encryptRole(role); // Cripta il ruolo prima di salvarlo
        } catch (Exception e) {
            throw new RuntimeException("Errore nella crittografia del ruolo", e);
        }

        User user = new User()
                .setFullName(input.getFullName())
                .setEmail(input.getEmail())
                .setPassword(passwordEncoder.encode(input.getPassword()))
                .setRole(encryptedRole);

        return userRepository.save(user);
    }

    // Metodo di utilità per la verifica del formato dell'email
    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }

    /**
     * Autentica un utente.
     * 
     * Questo metodo autentica un utente sulla base delle credenziali di accesso ricevute.
     * Usa AuthenticationManager per verificare email e password, quindi recupera l'utente dal database.
     *
     * @param input Dati dell'utente per l'autenticazione
     * @return L'utente autenticato trovato nel database
     * @throws InvalidTokenException se il token è scaduto o non valido
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
            throw new InvalidTokenException("Token JWT non valido o scaduto. Effettua nuovamente il login.");
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
