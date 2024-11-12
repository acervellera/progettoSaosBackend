package com.dib.uniba.services;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import com.github.bastiaanjansen.otp.TOTP;
import com.github.bastiaanjansen.otp.TOTPBuilder;

@Service
public class TwoFactorAuthService {

    @Value("${security.twofactor.encryption-key}")
    private String encryptionKey;

    public String generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
        keyGenerator.init(160);
        SecretKey secretKey = keyGenerator.generateKey();
        
        // Usa Base32 per la codifica
        Base32 base32 = new Base32();
        String plainSecret = base32.encodeToString(secretKey.getEncoded()).replace("=", ""); // Rimuovi padding "="

        // Cripta la chiave segreta in formato Base32 per salvarla nel database
        return encrypt(plainSecret);
    }

    public boolean validateOtpCode(String encryptedSecret, String code) {
        String decryptedSecret = decrypt(encryptedSecret);
        TOTP totp = new TOTPBuilder().withSecret(decryptedSecret.getBytes()).build();
        return totp.verify(code);
    }

    public String getOtpAuthUrl(String encryptedSecret, String email) {
        String decryptedSecret = decrypt(encryptedSecret);
        return "otpauth://totp/Microservizio1:" + email + "?secret=" + decryptedSecret + "&issuer=Microservizio1";
    }

    private String encrypt(String data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Errore nella crittografia", e);
        }
    }

    private String decrypt(String encryptedData) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Errore nella decrittografia", e);
        }
    }
}
