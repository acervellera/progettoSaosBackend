package com.dib.uniba.services;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.dib.uniba.entities.User;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Servizio per la gestione dei token JWT. Include metodi per generare, validare, e
 * estrarre informazioni dai token JWT.
 */
@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    /**
     * Estrae il nome utente (subject) dal token JWT.
     * 
     * @param token il token JWT da cui estrarre il nome utente
     * @return il nome utente contenuto nel token
     * @throws IllegalArgumentException in caso di errore durante l'estrazione
     */
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Errore durante l'estrazione del nome utente dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae un singolo claim dal token JWT utilizzando una funzione resolver.
     * 
     * @param token il token JWT
     * @param claimsResolver funzione per risolvere il claim
     * @param <T> tipo del claim da estrarre
     * @return il valore del claim estratto
     * @throws IllegalArgumentException in caso di errore durante l'estrazione
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        } catch (JwtException e) {
            throw new IllegalArgumentException("Errore durante l'estrazione dei claims dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Genera un token JWT senza claim extra.
     * 
     * @param userDetails dettagli dell'utente
     * @return il token JWT generato
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Genera un token JWT con claim extra specificati.
     * 
     * @param extraClaims claims aggiuntivi da includere nel token
     * @param userDetails dettagli dell'utente
     * @return il token JWT generato
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        if (userDetails instanceof User) {
            String role = ((User) userDetails).getRole();
            extraClaims.put("role", role);
        }
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Costruisce il token JWT utilizzando claims, nome utente e tempo di scadenza.
     * 
     * @param extraClaims claims extra da aggiungere al token
     * @param userDetails dettagli dell'utente
     * @param expiration tempo di scadenza del token
     * @return il token JWT costruito
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Verifica se il token JWT è valido per un utente specifico.
     * 
     * @param token il token JWT
     * @param userDetails dettagli dell'utente
     * @return true se il token è valido, false altrimenti
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Controlla se il token JWT è scaduto.
     * 
     * @param token il token JWT
     * @return true se il token è scaduto, false altrimenti
     */
    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            throw new IllegalArgumentException("Errore durante la verifica della scadenza del token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae la data di scadenza del token JWT.
     * 
     * @param token il token JWT
     * @return la data di scadenza del token
     * @throws IllegalArgumentException in caso di errore durante l'estrazione
     */
    private Date extractExpiration(String token) {
        try {
            return extractClaim(token, Claims::getExpiration);
        } catch (JwtException e) {
            throw new IllegalArgumentException("Errore durante l'estrazione della data di scadenza dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae tutti i claims dal token JWT.
     * 
     * @param token il token JWT
     * @return i claims estratti dal token
     * @throws IllegalArgumentException se il token è invalido o scaduto
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("Token JWT scaduto", e);
        } catch (MalformedJwtException e) {
            throw new IllegalArgumentException("Token JWT malformato", e);
        } catch (JwtException e) {
            throw new IllegalArgumentException("Token JWT non valido: " + e.getMessage(), e);
        }
    }

    /**
     * Ottiene la chiave di firma per il token JWT.
     * Decodifica la chiave segreta Base64 per creare la chiave.
     * 
     * @return la chiave di firma
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Estrae il ruolo dal token JWT.
     * 
     * @param token il token JWT
     * @return il ruolo dell'utente contenuto nel token
     * @throws IllegalArgumentException in caso di errore durante l'estrazione
     */
    public String extractRole(String token) {
        try {
            return extractClaim(token, claims -> claims.get("role", String.class));
        } catch (JwtException e) {
            throw new IllegalArgumentException("Errore durante l'estrazione del ruolo dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Restituisce il tempo di scadenza configurato per il token JWT.
     * 
     * @return tempo di scadenza in millisecondi
     */
    public long getExpirationTime() {
        return jwtExpiration;
    }
}
