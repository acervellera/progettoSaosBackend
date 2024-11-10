package com.dib.uniba.exception;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.security.access.AccessDeniedException;
import jakarta.validation.ConstraintViolationException;

/**
 * Gestore globale delle eccezioni che si occupa di gestire vari tipi di errori
 * e di restituire risposte HTTP appropriate per ciascun caso specifico.
 */
@ControllerAdvice
public class CustomGlobalExceptionHandler {

    /**
     * Gestisce errori di accesso non autorizzato e restituisce una risposta HTTP 403.
     *
     * @param ex eccezione AccessDeniedException catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 403
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        String errorMessage = "Accesso negato: non hai i permessi necessari per accedere a questa risorsa.";
        return new ResponseEntity<>(errorMessage, HttpStatus.FORBIDDEN);
    }

    /**
     * Gestisce eccezioni InvalidJwtTokenException per token JWT non validi o scaduti,
     * restituendo una risposta HTTP 401.
     *
     * @param ex eccezione InvalidJwtTokenException catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 401
     */
    @ExceptionHandler(InvalidJwtTokenException.class)
    public ResponseEntity<String> handleInvalidJwtTokenException(InvalidJwtTokenException ex) {
        String errorMessage = "Token JWT non valido o scaduto. Effettua nuovamente il login.";
        return new ResponseEntity<>(errorMessage, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Gestisce eccezioni IllegalArgumentException per token JWT non validi o scaduti,
     * restituendo una risposta HTTP 401.
     *
     * @param ex eccezione IllegalArgumentException catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 401
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleInvalidTokenException(IllegalArgumentException ex) {
        String errorMessage = "Token JWT non valido o scaduto. Effettua nuovamente il login.";
        return new ResponseEntity<>(errorMessage, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Gestisce violazioni di integrità dei dati, come duplicati di email, restituendo una risposta HTTP 409.
     *
     * @param ex eccezione DataIntegrityViolationException catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 409
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        String errorMessage = "L'email fornita è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT); // 409 Conflict
    }

    /**
     * Gestisce errori di violazione dei vincoli, come la duplicazione di email, restituendo una risposta HTTP 409.
     *
     * @param ex eccezione ConstraintViolationException catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 409
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleDuplicateEmailException(ConstraintViolationException ex) {
        String errorMessage = "L'email è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT); // 409 Conflict
    }

    /**
     * Gestisce tutte le altre eccezioni generiche, restituendo una risposta HTTP 500.
     *
     * @param ex eccezione generica catturata
     * @return ResponseEntity contenente il messaggio di errore e lo stato HTTP 500
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        String errorMessage = "Si è verificato un errore imprevisto. Riprova più tardi.";
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
