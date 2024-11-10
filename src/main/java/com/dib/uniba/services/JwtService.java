package com.dib.uniba.services;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Chiave segreta per firmare il JWT, letta dal file di configurazione
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    // Tempo di scadenza del token JWT, letto dal file di configurazione
    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    /**
     * Estrae il nome utente dal token JWT.
     * @param token Il token JWT da cui estrarre il nome utente
     * @return Il nome utente contenuto nel token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Estrae un singolo claim dal token JWT usando un resolver.
     * @param token Il token JWT
     * @param claimsResolver Funzione per risolvere il claim
     * @param <T> Tipo del claim da estrarre
     * @return Il valore del claim estratto
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Genera un token JWT per un utente specifico senza claim extra.
     * @param userDetails Dettagli dell'utente
     * @return Il token JWT generato
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Genera un token JWT con claim extra.
     * @param extraClaims Claims aggiuntivi da includere nel token
     * @param userDetails Dettagli dell'utente
     * @return Il token JWT generato
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Costruisce il token JWT utilizzando i claim, nome utente e tempo di scadenza specificati.
     * @param extraClaims Claims extra da aggiungere al token
     * @param userDetails Dettagli dell'utente
     * @param expiration Tempo di scadenza del token
     * @return Il token JWT costruito
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Firma il token con la chiave segreta
                .compact();
    }

    /**
     * Verifica se il token JWT è valido per un utente specifico.
     * @param token Il token JWT
     * @param userDetails Dettagli dell'utente
     * @return True se il token è valido, False altrimenti
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Controlla se il token JWT è scaduto.
     * @param token Il token JWT
     * @return True se il token è scaduto, False altrimenti
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Estrae la data di scadenza del token JWT.
     * @param token Il token JWT
     * @return La data di scadenza del token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Estrae tutti i claims dal token JWT.
     * @param token Il token JWT
     * @return I claims estratti dal token
     * @throws IllegalArgumentException se il token è invalido
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            // Gestisce eccezioni specifiche del JWT come ExpiredJwtException o MalformedJwtException
            throw new IllegalArgumentException("Invalid JWT token");
        }
    }

    /**
     * Ottiene la chiave di firma per il token JWT.
     * Decodifica la chiave segreta Base64 per creare la chiave.
     * @return La chiave di firma
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public long getExpirationTime() {
        return jwtExpiration;
    }

}
