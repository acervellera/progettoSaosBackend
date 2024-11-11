package com.dib.uniba.exception;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import jakarta.validation.ConstraintViolationException;

/**
 * Gestore globale delle eccezioni che si occupa di gestire vari tipi di errori
 * e di restituire risposte HTTP appropriate per ciascun caso specifico.
 */
@ControllerAdvice
public class CustomGlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        String errorMessage = "Accesso negato: non hai i permessi necessari per accedere a questa risorsa.";
        return new ResponseEntity<>(errorMessage, HttpStatus.FORBIDDEN);
    }

    // Gestisce InvalidTokenException per token JWT non validi o scaduti
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<String> handleInvalidTokenException(InvalidTokenException ex) {
        String errorMessage = "Credenziali errate. Riprovare";
        return new ResponseEntity<>(errorMessage, HttpStatus.UNAUTHORIZED);
    }

    // Gestisce InvalidArgumentCustomException per argomenti non validi in altri contesti
    @ExceptionHandler(InvalidArgumentCustomException.class)
    public ResponseEntity<String> handleInvalidArgument(InvalidArgumentCustomException ex) {
        String errorMessage = ex.getMessage();
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        String errorMessage = "L'email fornita è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleDuplicateEmailException(ConstraintViolationException ex) {
        String errorMessage = "L'email è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<String> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        String errorMessage = "email o password non valide. Riprovare.";
        return new ResponseEntity<>(errorMessage, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        String errorMessage = "Si è verificato un errore imprevisto. Riprova più tardi.";
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
