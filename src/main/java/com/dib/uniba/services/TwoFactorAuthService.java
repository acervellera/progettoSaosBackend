package com.dib.uniba.services;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.apache.commons.codec.binary.Base32;
import org.jboss.aerogear.security.otp.Totp;


@Service
public class TwoFactorAuthService {

    @Value("${security.twofactor.encryption-key}")
    private String encryptionKey;

    // Genera la chiave TOTP in formato Base32 e la cifra
    public String generateSecretKey() {
        try {
            // Step 1: Genera 10 byte casuali per la chiave TOTP
            byte[] secretBytes = new byte[10]; // 80 bit
            new SecureRandom().nextBytes(secretBytes);

            // Step 2: Codifica la chiave in Base32 per Google Authenticator
            Base32 base32 = new Base32();
            String totpSecretKeyBase32 = base32.encodeToString(secretBytes).replace("=", "");
            
            // Debug: stampa la chiave TOTP generata
            System.out.println("Chiave TOTP in Base32 (per Google Authenticator): " + totpSecretKeyBase32);

            // Step 3: Cripta la chiave TOTP in formato byte[] e restituiscila in Base64
            return encrypt(secretBytes);

        } catch (Exception e) {
            throw new RuntimeException("Errore nella generazione o crittografia della chiave TOTP", e);
        }
    }
    
    public boolean validateOtpCode(String encryptedSecret, String code) {
        // Decodifica e decripta la chiave segreta per ottenere il byte[] originale
        byte[] decryptedSecretBytes = decrypt(encryptedSecret);

        // Codifica nuovamente la chiave decriptata in Base32 per AeroGear Totp
        Base32 base32 = new Base32();
        String base32Secret = base32.encodeToString(decryptedSecretBytes).replace("=", "");

        // Usa la chiave in formato Base32 per creare un'istanza di Totp
        Totp totp = new Totp(base32Secret);

        // Genera e stampa il codice TOTP per debug
        String generatedCode = totp.now();
        System.out.println("Codice TOTP generato: " + generatedCode);
        System.out.println("Codice TOTP inserito dall'utente: " + code);

        // Verifica il codice OTP
        return totp.verify(code);
    }
    
    
    public String getOtpAuthUrl(String encryptedSecret, String email) {
        byte[] decryptedSecret = decrypt(encryptedSecret); // Decodifica in byte[]
        Base32 base32 = new Base32();
        String base32Secret = base32.encodeToString(decryptedSecret).replace("=", ""); // Rimuove padding "="
        
        return "otpauth://totp/Microservizio1:" + email + "?secret=" + base32Secret + "&issuer=Microservizio1";
    }

    // Funzione di crittografia AES per la chiave
    private String encrypt(byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encryptedData = cipher.doFinal(data);
            String base64EncodedData = Base64.getEncoder().encodeToString(encryptedData);
            
            // Stampa o verifica i dati intermedi   DA CANCELLARE PER DEBUG
            System.out.println("Dati criptati (byte[]): " + Arrays.toString(encryptedData));
            System.out.println("Dati criptati in Base64: " + base64EncodedData);
            
            return base64EncodedData;
        } catch (Exception e) {
            throw new RuntimeException("Errore nella crittografia", e);
        }
    }

    // Funzione di decrittografia AES per ottenere il byte[] della chiave
    private byte[] decrypt(String encryptedData) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            byte[] decodedBase64Data = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedData = cipher.doFinal(decodedBase64Data);
            
            // Stampa o verifica i dati intermedi  DA CANCELLARE PER DEBUG
            System.out.println("Dati decodificati da Base64 (byte[]): " + Arrays.toString(decodedBase64Data));
            System.out.println("Dati decriptati (byte[]): " + Arrays.toString(decryptedData));
            
            return decryptedData;
        } catch (Exception e) {
            throw new RuntimeException("Errore nella decrittografia", e);
        }
    }

}
