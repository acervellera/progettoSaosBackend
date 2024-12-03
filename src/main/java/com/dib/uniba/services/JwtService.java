package com.dib.uniba.services;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.dib.uniba.entities.User;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Servizio per la gestione dei token JWT. Include metodi per generare,
 * validare, e
 * estrarre informazioni dai token JWT.
 */
@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.aes-key}")
    private String aesKey; // Chiave AES dinamica letta da application.properties

    /**
     * Estrae il nome utente (subject) dal token JWT.
     */
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Errore durante l'estrazione del nome utente dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae un singolo claim dal token JWT utilizzando una funzione resolver.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        } catch (JwtException e) {
            throw new IllegalArgumentException(
                    "Errore durante l'estrazione dei claims dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Genera un token JWT senza claim extra.
     */
    public String generateToken(UserDetails userDetails) {
        String token = generateToken(new HashMap<>(), userDetails); // Assegna il token generato
        try {
            token = encryptToken(token); // Cripta il token
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting the token", e);
        }
        return token;
    }

    /**
     * Genera un token JWT con claim extra specificati.
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
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Controlla se il token JWT è scaduto.
     */
    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            throw new IllegalArgumentException(
                    "Errore durante la verifica della scadenza del token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae la data di scadenza del token JWT.
     */
    private Date extractExpiration(String token) {
        try {
            return extractClaim(token, Claims::getExpiration);
        } catch (JwtException e) {
            throw new IllegalArgumentException(
                    "Errore durante l'estrazione della data di scadenza dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Estrae tutti i claims dal token JWT.
     */
    private Claims extractAllClaims(String token) {
        try {
            token = decryptToken(token);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting the token", e);
        }
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
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Estrae il ruolo dal token JWT.
     */
    public String extractRole(String token) {
        try {
            return extractClaim(token, claims -> claims.get("role", String.class));
        } catch (JwtException e) {
            throw new IllegalArgumentException(
                    "Errore durante l'estrazione del ruolo dal token JWT: " + e.getMessage());
        }
    }

    /**
     * Restituisce il tempo di scadenza configurato per il token JWT.
     */
    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String encryptToken(String jwt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(jwt.getBytes()));
    }

    private String decryptToken(String encryptedJwt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedJwt)));
    }

}
