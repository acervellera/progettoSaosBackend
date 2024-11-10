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

import io.jsonwebtoken.JwtException;

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

        // Log dell'header per verificare la presenza e il formato corretto
        logger.info("Authorization Header: " + authHeader);

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
        } catch (JwtException e) {
            logger.warning("Errore nella validazione del token: " + e.getMessage());
            response.reset();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            String errorMessage = "{\"error\": \"Token JWT non valido o scaduto. Effettua nuovamente il login.\"}";
            response.setContentLength(errorMessage.length());
            response.getWriter().write(errorMessage);
            response.getWriter().flush();
            return;
        }

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Verifica della validità del token con un controllo forzato
            if (!jwtService.isTokenValid(jwt, userDetails)) {
                logger.warning("Token non valido per l'utente: " + userEmail);
                response.reset();
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType("application/json");
                String errorMessage = "{\"error\": \"Token JWT non valido o scaduto. Effettua nuovamente il login.\"}";
                response.setContentLength(errorMessage.length());
                response.getWriter().write(errorMessage);
                response.getWriter().flush();
                return;
            }

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
}
