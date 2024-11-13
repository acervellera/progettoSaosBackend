package com.dib.uniba.controllers;

import com.dib.uniba.entities.User;
import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.responses.LoginResponse;
import com.dib.uniba.services.AuthenticationService;
import com.dib.uniba.services.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * Controller per la gestione delle autenticazioni e delle registrazioni degli utenti.
 * Fornisce gli endpoint per la registrazione e il login di utenti e amministratori.
 */
@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    /**
     * Costruttore per l'iniezione delle dipendenze JwtService e AuthenticationService.
     *
     * @param jwtService            servizio per la generazione e gestione dei token JWT
     * @param authenticationService servizio per la gestione delle autenticazioni e registrazioni
     */
    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    /**
     * Endpoint per la registrazione di un nuovo utente con ruolo "USER".
     *
     * @param registerUserDto oggetto contenente i dettagli dell'utente da registrare
     * @return ResponseEntity contenente l'utente registrato e lo stato HTTP
     * @throws NoSuchAlgorithmException 
     */
    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@RequestBody RegisterUserDto registerUserDto) throws NoSuchAlgorithmException {
        User registeredUser = authenticationService.signup(registerUserDto, "USER"); // Ruolo di default "USER"
        return ResponseEntity.ok(registeredUser);
    }

    /**
     * Endpoint per la registrazione di un nuovo amministratore con ruolo "ADMIN".
     *
     * @param registerUserDto oggetto contenente i dettagli dell'amministratore da registrare
     * @return ResponseEntity contenente l'amministratore registrato e lo stato HTTP
     * @throws NoSuchAlgorithmException 
     */
    @PostMapping("/admin/signup")
    public ResponseEntity<User> registerAdmin(@RequestBody RegisterUserDto registerUserDto) throws NoSuchAlgorithmException {
        User registeredAdmin = authenticationService.signup(registerUserDto, "ADMIN"); // Ruolo specifico "ADMIN"
        return ResponseEntity.ok(registeredAdmin);
    }

    /**
     * Endpoint per l'inizializzazione della 2FA per un utente, generando un URL OTP.
     *
     * @param email Email dell'utente per la 2FA
     * @return URL OTP da scansionare per abilitare la 2FA
     * @throws NoSuchAlgorithmException in caso di errore nella generazione della chiave segreta
     */
    @PostMapping("/initiate-2fa")
    public ResponseEntity<String> initiateTwoFactorAuth(@RequestBody Map<String, String> requestBody) throws NoSuchAlgorithmException {
        String email = requestBody.get("email");
        String otpAuthUrl = authenticationService.initiateTwoFactorAuth(email);
        return ResponseEntity.ok(otpAuthUrl);
    }


    /**
     * Endpoint per il login con autenticazione a due fattori (email, password e OTP).
     *
     * @param loginUserDto oggetto contenente le credenziali dell'utente per il login
     * @param otpCode      codice OTP generato dall'app Google Authenticator
     * @return ResponseEntity contenente il token JWT e il tempo di scadenza
     */
    @PostMapping("/login-2fa")
    public ResponseEntity<LoginResponse> loginWithTwoFactor(@RequestBody LoginUserDto loginUserDto, @RequestParam String otpCode) {
        String jwtToken = authenticationService.login(loginUserDto.getEmail(), loginUserDto.getPassword(), otpCode);

        // Crea la risposta di login contenente il token e il tempo di scadenza
        LoginResponse loginResponse = new LoginResponse()
                .setToken(jwtToken)
                .setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }

    /**
     * Endpoint per l'autenticazione dell'utente senza 2FA. Genera un token JWT per l'utente autenticato.
     *
     * @param loginUserDto oggetto contenente le credenziali dell'utente per il login
     * @return ResponseEntity contenente il token JWT e il tempo di scadenza
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        User authenticatedUser = authenticationService.authenticate(loginUserDto);

        // Genera il token JWT per l'utente autenticato
        String jwtToken = jwtService.generateToken(authenticatedUser);

        // Crea la risposta di login contenente il token e il tempo di scadenza
        LoginResponse loginResponse = new LoginResponse()
                .setToken(jwtToken)
                .setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }
}
