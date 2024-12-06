package com.dib.uniba.controllers;

import com.dib.uniba.entities.User;
import com.dib.uniba.exception.UnauthorizedAccessException;
import com.dib.uniba.dtos.LoginUserDto;
import com.dib.uniba.dtos.RegisterUserDto;
import com.dib.uniba.responses.LoginResponse;
import com.dib.uniba.services.AuthenticationService;
import com.dib.uniba.services.JwtService;
import com.dib.uniba.services.QrCodeService;
import com.dib.uniba.services.TokenService;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller per la gestione delle autenticazioni e delle registrazioni degli utenti.
 * Fornisce gli endpoint per la registrazione, il login e la gestione della 2FA.
 */
@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final QrCodeService qrCodeService;
    private final TokenService tokenService;

    /**
     * Costruttore per l'iniezione delle dipendenze JwtService, AuthenticationService e QrCodeService.
     *
     * @param jwtService            servizio per la generazione e gestione dei token JWT
     * @param authenticationService servizio per la gestione delle autenticazioni e registrazioni
     * @param qrCodeService         servizio per la generazione dei QR Code
     */
    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService, QrCodeService qrCodeService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.qrCodeService = qrCodeService;
		this.tokenService = new TokenService();
    }

    /**
     * Endpoint per la registrazione di un nuovo utente con ruolo "USER".
     *
     * @param registerUserDto oggetto contenente i dettagli dell'utente da registrare
     * @return ResponseEntity contenente l'utente registrato e lo stato HTTP
     * @throws NoSuchAlgorithmException in caso di errore nella generazione della chiave
     */
    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> registerUser(@RequestBody RegisterUserDto registerUserDto) throws NoSuchAlgorithmException {
        User registeredUser = authenticationService.signup(registerUserDto, "USER");

        String temporaryToken = tokenService.generateTemporaryToken(registeredUser.getEmail()); // Genera un token temporaneo

        Map<String, String> response = new HashMap<>();
        response.put("message", "Registrazione completata. Configura la 2FA.");
        response.put("email", registeredUser.getEmail());
        response.put("temporaryToken", temporaryToken); // Invia il token temporaneo

        return ResponseEntity.ok(response);
    }



    /**
     * Endpoint per la registrazione di un nuovo amministratore con ruolo "ADMIN".
     *
     * @param registerUserDto oggetto contenente i dettagli dell'amministratore da registrare
     * @return ResponseEntity contenente l'amministratore registrato e lo stato HTTP
     * @throws NoSuchAlgorithmException in caso di errore nella generazione della chiave
     */
    @PostMapping("/admin/signup")
    public ResponseEntity<User> registerAdmin(@RequestBody RegisterUserDto registerUserDto) throws NoSuchAlgorithmException {
        User registeredAdmin = authenticationService.signup(registerUserDto, "ADMIN");
        return ResponseEntity.ok(registeredAdmin);
    }

    /**
     * Endpoint per l'inizializzazione della 2FA per un utente, generando un URL OTP e un QR Code.
     *
     * @param requestBody Map contenente l'email dell'utente per la 2FA
     * @return QR Code in formato PNG da scansionare per abilitare la 2FA
     * @throws NoSuchAlgorithmException in caso di errore nella generazione della chiave segreta
     */
    @PostMapping(value = "/initiate-2fa", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> initiateTwoFactorAuth(@RequestBody Map<String, String> requestBody) throws NoSuchAlgorithmException {
        String email = requestBody.get("email");
        String temporaryToken = requestBody.get("temporaryToken");

        // Verifica il token temporaneo
        if (!tokenService.isTemporaryTokenValid(email, temporaryToken)) {
            throw new UnauthorizedAccessException("Accesso non autorizzato. Devi registrarti per accedere a questa risorsa.");
        }

        String otpAuthUrl = authenticationService.initiateTwoFactorAuth(email);

        try {
            byte[] qrImage = qrCodeService.generateQrCode(otpAuthUrl, 300, 300);
            return ResponseEntity.ok(qrImage);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
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
