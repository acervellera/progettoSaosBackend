package com.dib.uniba.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.dib.uniba.services.JwtService;

import java.io.IOException;
import java.util.logging.Logger;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private static final Logger logger = Logger.getLogger(JwtAuthenticationFilter.class.getName());

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        logger.info("Authorization Header: " + authHeader);

        // Controlla se l'header è nullo o non contiene "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        logger.info("JWT Token estratto: " + jwt);

        final String userEmail;
        try {
            userEmail = jwtService.extractUsername(jwt);
            logger.info("Email estratta dal token: " + userEmail);
        } catch (IllegalArgumentException e) {
            logger.warning("Errore nella validazione del token: " + e.getMessage());
            setUnauthorizedResponse(response, e.getMessage());
            return; // Termina la catena del filtro se il token è invalido
        }

        // Verifica che l'email non sia nulla e che non ci sia già un'auth nel contesto
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Valida il token
            if (!jwtService.isTokenValid(jwt, userDetails)) {
                logger.warning("Token non valido per l'utente: " + userEmail);
                setUnauthorizedResponse(response, "Token JWT non valido o scaduto. Effettua nuovamente il login.");
                return;
            }

            // Crea il token di autenticazione
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        filterChain.doFilter(request, response);
    }

    private void setUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.reset();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        String errorMessage = String.format("{\"error\": \"%s\"}", message);
        response.getWriter().write(errorMessage);
        response.getWriter().flush();
    }

}
