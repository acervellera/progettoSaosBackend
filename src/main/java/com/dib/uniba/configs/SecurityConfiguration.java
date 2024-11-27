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

/**
 * Classe di configurazione della sicurezza per l'applicazione.
 * Configura le autorizzazioni per gli endpoint, la gestione delle sessioni,
 * il CORS e la gestione delle eccezioni per gli accessi non autorizzati.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    /**
     * Costruttore della classe SecurityConfiguration.
     *
     * @param jwtAuthenticationFilter    filtro di autenticazione JWT personalizzato
     * @param authenticationProvider     provider di autenticazione per la gestione degli utenti
     * @param customAccessDeniedHandler  gestore per accessi negati
     */
    public SecurityConfiguration(
        JwtAuthenticationFilter jwtAuthenticationFilter,
        AuthenticationProvider authenticationProvider,
        CustomAccessDeniedHandler customAccessDeniedHandler
    ) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }

    /**
     * Configura la catena di sicurezza, compresi i filtri, le autorizzazioni,
     * la gestione delle eccezioni e le policy di sessione.
     *
     * @param http oggetto HttpSecurity per configurare la sicurezza
     * @return un oggetto SecurityFilterChain configurato
     * @throws Exception in caso di errori di configurazione
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disabilita la protezione CSRF poiché l'app usa autenticazione JWT
            .csrf(csrf -> csrf.disable())
            // Configura autorizzazioni per specifici endpoint
            .authorizeHttpRequests(auth -> auth
            	    .requestMatchers("/auth/login-2fa").permitAll()  // Accessibile a tutti
            	    .requestMatchers("/auth/initiate-2fa").permitAll()  // Accessibile a tutti
            	    .requestMatchers("/auth/request-password-reset").permitAll()  // Aggiunto per il reset password
            	    .requestMatchers("/auth/reset-password").permitAll()  // Aggiunto per il reset password
            	    .requestMatchers("/auth/signup").permitAll()  // Accessibile a tutti
            	    .requestMatchers("/auth/login").permitAll()   // Accessibile a tutti
            	    .requestMatchers("/auth/admin/signup").hasRole("ADMIN")  // Solo per ADMIN
            	    .anyRequest().authenticated()  // Tutto il resto richiede autenticazione
            	)

            // Configura la gestione delle eccezioni per accessi non autorizzati
            .exceptionHandling(exception -> exception
                .accessDeniedHandler(customAccessDeniedHandler) // Imposta il gestore per accessi negati
            )
            // Imposta la gestione delle sessioni come stateless (senza sessione)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // Configura il provider di autenticazione
            .authenticationProvider(authenticationProvider)
            // Aggiunge il filtro JWT prima del filtro di autenticazione basato su nome utente e password
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configura le regole CORS per l'applicazione, consentendo richieste da origini specificate.
     *
     * @return l'oggetto CorsConfigurationSource configurato
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:8082", "http://localhost:8080", "http://localhost:8081"));
        configuration.setAllowedMethods(List.of("GET", "POST"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
