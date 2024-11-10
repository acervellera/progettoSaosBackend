package com.dib.uniba.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    // Dependences for managing authentication and JWT filtering
    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // Constructor injection of dependencies
    public SecurityConfiguration(
        JwtAuthenticationFilter jwtAuthenticationFilter,
        AuthenticationProvider authenticationProvider
    ) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Configura la catena di filtri di sicurezza HTTP.
     * Disabilita CSRF, configura le autorizzazioni per le richieste HTTP, 
     * gestisce la sessione e aggiunge il filtro di autenticazione JWT.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/signup").permitAll()    // Accesso libero per registrazione utenti
                .requestMatchers("/auth/login").permitAll()     // Accesso libero per login
                .requestMatchers("/auth/admin/signup").hasRole("ADMIN") // Solo gli ADMIN possono registrare altri admin
                .anyRequest().authenticated()                   // Tutte le altre richieste richiedono autenticazione
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configura  il CORS (Cross-Origin Resource Sharing) per permettere l'accesso da origini specifiche.
     * Permette specifici metodi HTTP e headers per l'accesso.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Configura le origini consentite per le richieste
        configuration.setAllowedOrigins(List.of("http://localhost:8082", "http://localhost:8080","http://localhost:8081"));

        // Specifica i metodi HTTP consentiti
        configuration.setAllowedMethods(List.of("GET","POST"));
        // Specifica gli headers consentiti
        configuration.setAllowedHeaders(List.of("Authorization","Content-Type"));

        // Associa la configurazione CORS agli endpoint
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Applica la configurazione a tutti gli endpoint

        return source; // Restituisce la configurazione CORS
    }
}
