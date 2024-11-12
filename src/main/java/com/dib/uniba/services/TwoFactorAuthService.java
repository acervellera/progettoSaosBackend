package com.dib.uniba.services;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.SecretGenerator;
import com.bastiaanjansen.otp.TOTPGenerator;

@Service
public class TwoFactorAuthService {

    @Value("${security.twofactor.encryption-key}")
    private String encryptionKey;

    public String generateSecretKey() throws NoSuchAlgorithmException {
        byte[] secret = SecretGenerator.generate();
        Base32 base32 = new Base32();
        String plainSecret = base32.encodeToString(secret).replace("=", ""); 
        return encrypt(plainSecret);
    }

    public boolean validateOtpCode(String encryptedSecret, String code) {
        String decryptedSecret = decrypt(encryptedSecret);
        
        Base32 base32 = new Base32();
        byte[] secretBytes = base32.decode(decryptedSecret);

        // Configura e crea il TOTPGenerator usando l'algoritmo HMAC e un periodo di 30 secondi
        TOTPGenerator totpGenerator = new TOTPGenerator.Builder(secretBytes)
                .withHOTPGenerator(hotpBuilder -> {
                    hotpBuilder.withPasswordLength(6);
                    hotpBuilder.withAlgorithm(HMACAlgorithm.SHA1);
                })
                .withPeriod(Duration.ofSeconds(30))
                .build();
        
        // Verifica il codice OTP
        return totpGenerator.verify(code);
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

