package com.dib.uniba.controllers;

import com.dib.uniba.entities.User;
import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.responses.LoginResponse;
import com.dib.uniba.services.AuthenticationService;
import com.dib.uniba.services.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
     */
    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.signup(registerUserDto, "USER"); // Ruolo di default "USER"
        return ResponseEntity.ok(registeredUser);
    }

    /**
     * Endpoint per la registrazione di un nuovo amministratore con ruolo "ADMIN".
     *
     * @param registerUserDto oggetto contenente i dettagli dell'amministratore da registrare
     * @return ResponseEntity contenente l'amministratore registrato e lo stato HTTP
     */
    @PostMapping("/admin/signup")
    public ResponseEntity<User> registerAdmin(@RequestBody RegisterUserDto registerUserDto) {
        User registeredAdmin = authenticationService.signup(registerUserDto, "ADMIN"); // Ruolo specifico "ADMIN"
        return ResponseEntity.ok(registeredAdmin);
    }

    /**
     * Endpoint per l'autenticazione dell'utente. Genera un token JWT per l'utente autenticato.
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
