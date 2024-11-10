package com.dib.uniba.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.dib.uniba.repositories.UserRepository;

@Configuration
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    // Costruttore della classe che inizializza il repository degli utenti
    public ApplicationConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Crea e restituisce un bean di UserDetailsService.
     * Questo metodo cerca un utente nel repository tramite email.
     * Se l'utente non viene trovato, viene lanciata un'eccezione.
     */
    @Bean
     UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Utente non trovato"));
    }

    /**
     * Crea e restituisce un bean di BCryptPasswordEncoder.
     * Questo bean viene utilizzato per criptare le password degli utenti.
     */
    @Bean
     BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Crea e restituisce un bean di AuthenticationManager.
     * Viene utilizzato per gestire l'autenticazione nel contesto di Spring Security.
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Crea e restituisce un bean di AuthenticationProvider.
     * Questo provider di autenticazione utilizza DaoAuthenticationProvider,
     * configurato con il servizio utenti e l'encoder di password.
     */
    @Bean
     AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); // Configura UserDetailsService
        authProvider.setPasswordEncoder(passwordEncoder());       // Configura BCryptPasswordEncoder
        return authProvider;
    }
}

