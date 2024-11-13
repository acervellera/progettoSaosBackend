package com.dib.uniba.services;

import java.security.NoSuchAlgorithmException;
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

/**
 * Servizio per la gestione dell'autenticazione, registrazione e autenticazione a due fattori (2FA).
 * Contiene metodi per la registrazione di nuovi utenti, autenticazione con password e OTP, 
 * e generazione di URL OTP per la scansione con Google Authenticator.
 */
@Service
public class AuthenticationService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RoleEncryptionUtil roleEncryptionUtil;
    private final TwoFactorAuthService twoFactorAuthService;
    private final JwtService jwtService;

    /**
     * Costruttore di AuthenticationService con iniezione delle dipendenze.
     * 
     * @param userRepository repository per la gestione degli utenti
     * @param authenticationManager gestore per l'autenticazione degli utenti
     * @param passwordEncoder encoder per la codifica delle password
     * @param roleEncryptionUtil utilità per la crittografia dei ruoli
     * @param twoFactorAuthService servizio per la gestione della 2FA
     */
    public AuthenticationService(
        UserRepository userRepository,
        AuthenticationManager authenticationManager,
        PasswordEncoder passwordEncoder,
        RoleEncryptionUtil roleEncryptionUtil,
        TwoFactorAuthService twoFactorAuthService,
        JwtService jwtService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleEncryptionUtil = roleEncryptionUtil;
        this.twoFactorAuthService = twoFactorAuthService;
        this.jwtService = jwtService;
    }


    /**
     * Inizia la procedura di autenticazione a due fattori (2FA) per un utente,
     * generando una chiave segreta se non esiste e restituendo l'URL OTP per Google Authenticator.
     *
     * @param email L'email dell'utente
     * @return L'URL OTP da scansionare in Google Authenticator
     * @throws NoSuchAlgorithmException se l'algoritmo di generazione della chiave non è supportato
     */
    public String initiateTwoFactorAuth(String email) throws NoSuchAlgorithmException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        // Genera una chiave segreta se non è già presente
        String secretKey = user.getTwoFactorSecret();
        if (secretKey == null) {
            secretKey = twoFactorAuthService.generateSecretKey();
            user.setTwoFactorSecret(secretKey);
            userRepository.save(user); // Salva la chiave nel database
        }

        return twoFactorAuthService.getOtpAuthUrl(secretKey, email); // Restituisce l'URL OTP
    }

    /**
     * Esegue il login dell'utente con verifica della password e codice OTP.
     *
     * @param email L'email dell'utente
     * @param password La password dell'utente
     * @param otpCode Il codice OTP generato dall'app Google Authenticator
     * @return Token JWT per l'accesso dell'utente
     */
    public String login(String email, String password, String otpCode) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Verifica la password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidArgumentCustomException("Password non valida");
        }

        // Verifica il codice OTP
        String secretKey = user.getTwoFactorSecret();
        if (secretKey != null) {
            boolean isOtpValid = twoFactorAuthService.validateOtpCode(secretKey, otpCode);
            if (!isOtpValid) {
                throw new InvalidArgumentCustomException("Codice OTP non valido");
            }
        }

        // Genera e restituisce il token JWT
        return jwtService.generateToken(user);
    }

    /**
     * Registra un nuovo utente. 
     * Verifica la lunghezza della password, la validità dell'email e la sua unicità.
     * 
     * @param input Dati dell'utente da registrare
     * @param role Ruolo dell'utente (USER o ADMIN)
     * @return L'utente appena creato e salvato nel database
     * @throws InvalidArgumentCustomException se la password è inferiore a 8 caratteri o se l'email non è valida
     */
    public User signup(RegisterUserDto input, String role) throws NoSuchAlgorithmException {
        if (input.getPassword().length() < 8) {
            throw new InvalidArgumentCustomException("La password deve essere lunga almeno 8 caratteri.");
        }

        if (!isValidEmail(input.getEmail())) {
            throw new InvalidArgumentCustomException("Formato email non valido.");
        }

        if (userRepository.findByEmail(input.getEmail()).isPresent()) {
            throw new InvalidArgumentCustomException("Email già esistente. Scegli un'altra email.");
        }

        String encryptedRole;
        try {
            encryptedRole = roleEncryptionUtil.encryptRole(role);
        } catch (Exception e) {
            throw new RuntimeException("Errore nella crittografia del ruolo", e);
        }

        // Genera twoFactorSecret
        String twoFactorSecret;
        twoFactorSecret = twoFactorAuthService.generateSecretKey();

        User user = new User()
                .setFullName(input.getFullName())
                .setEmail(input.getEmail())
                .setPassword(passwordEncoder.encode(input.getPassword()))
                .setRole(encryptedRole)
                .setTwoFactorSecret(twoFactorSecret);

        return userRepository.save(user);
    }
    /**
     * Autentica un utente sulla base delle credenziali di accesso ricevute.
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
            String decryptedRole = roleEncryptionUtil.decryptRole(user.getRole());
            user.setRole(decryptedRole);
        } catch (Exception e) {
            throw new RuntimeException("Errore nella decrittografia del ruolo", e);
        }

        return user;
    }

    /**
     * Verifica la validità del formato email.
     *
     * @param email Email da verificare
     * @return true se il formato è valido, false altrimenti
     */
    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }
}
