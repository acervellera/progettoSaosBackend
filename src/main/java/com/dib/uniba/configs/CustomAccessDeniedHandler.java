package com.dib.uniba.configs;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Classe `CustomAccessDeniedHandler` che implementa `AccessDeniedHandler`.
 * Gestisce i casi in cui un utente tenta di accedere a una risorsa protetta senza le autorizzazioni necessarie,
 * restituendo una risposta personalizzata con codice di stato 403 e un messaggio di errore in formato JSON.
 */
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    /**
     * Metodo per gestire i tentativi di accesso non autorizzati.
     *
     * Questo metodo viene chiamato automaticamente quando un utente tenta di accedere a una risorsa
     * per cui non ha i permessi necessari. Imposta lo stato della risposta HTTP a 403 (FORBIDDEN)
     * e restituisce un messaggio di errore in formato JSON che indica che l'accesso è negato.
     *
     * @param request               l'oggetto HttpServletRequest della richiesta
     * @param response              l'oggetto HttpServletResponse della risposta
     * @param accessDeniedException l'eccezione lanciata in caso di accesso negato
     * @throws IOException      se si verifica un errore di input/output durante la scrittura della risposta
     * @throws ServletException se si verifica un errore durante l'elaborazione della richiesta
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // Imposta il codice di stato HTTP a 403 (FORBIDDEN) per indicare che l'accesso è negato
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // Imposta il tipo di contenuto della risposta a JSON
        response.setContentType("application/json");

        // Messaggio di errore JSON che verrà restituito al client
        String errorMessage = "{\"error\": \"Accesso negato: non hai i permessi necessari per questa risorsa.\"}";

        // Scrive il messaggio di errore nella risposta
        response.getWriter().write(errorMessage);
        response.getWriter().flush(); // Forza la scrittura immediata della risposta
    }
}
