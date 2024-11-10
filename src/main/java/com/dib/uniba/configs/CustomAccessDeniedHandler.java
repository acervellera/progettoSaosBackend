package com.dib.uniba.configs;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException; // Assicurati di utilizzare `jakarta.servlet` se sei su Jakarta EE
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        String errorMessage = "{\"error\": \"Accesso negato: non hai i permessi necessari per questa risorsa.\"}";
        response.getWriter().write(errorMessage);
        response.getWriter().flush();
    }
}
