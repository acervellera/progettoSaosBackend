package com.dib.uniba.exception;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.security.access.AccessDeniedException;
import jakarta.validation.ConstraintViolationException;

@ControllerAdvice
public class CustomGlobalExceptionHandler {

    // Gestisce errori di accesso non autorizzato (403)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        String errorMessage = "Accesso negato: non hai i permessi necessari per accedere a questa risorsa.";
        return new ResponseEntity<>(errorMessage, HttpStatus.FORBIDDEN);
    }

    // Gestisce token non validi o scaduti tramite InvalidJwtTokenException
    @ExceptionHandler(InvalidJwtTokenException.class)
    public ResponseEntity<String> handleInvalidJwtTokenException(InvalidJwtTokenException ex) {
        String errorMessage = "Token JWT non valido o scaduto. Effettua nuovamente il login.";
        return new ResponseEntity<>(errorMessage, HttpStatus.UNAUTHORIZED);
    }

    // Gestisce token non validi o scaduti tramite IllegalArgumentException
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleInvalidTokenException(IllegalArgumentException ex) {
        String errorMessage = "Token JWT non valido o scaduto. Effettua nuovamente il login.";
        return new ResponseEntity<>(errorMessage, HttpStatus.UNAUTHORIZED);
    }

    // Gestisce errori di duplicazione (come l'email duplicata)
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        String errorMessage = "L'email fornita è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT); // 409 Conflict
    }

    // Gestisce l'errore di duplicazione email (esempio, usa il tuo caso specifico di eccezione)
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleDuplicateEmailException(ConstraintViolationException ex) {
        String errorMessage = "L'email è già esistente. Scegli un'altra email.";
        return new ResponseEntity<>(errorMessage, HttpStatus.CONFLICT); // 409 Conflict
    }

    // Gestisce tutte le altre eccezioni generiche
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        String errorMessage = "Si è verificato un errore imprevisto. Riprova più tardi.";
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
