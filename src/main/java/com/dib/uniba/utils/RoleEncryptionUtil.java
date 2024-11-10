package com.dib.uniba.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class RoleEncryptionUtil {

    private static final String ALGORITHM = "AES";
    private final SecretKeySpec keySpec;

    // Carica la chiave dal file di configurazione
    public RoleEncryptionUtil(@Value("${security.encryption.key}") String secretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        this.keySpec = new SecretKeySpec(decodedKey, ALGORITHM);
    }

    public String encryptRole(String role) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(role.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptRole(String encryptedRole) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedRole);
        return new String(cipher.doFinal(decodedBytes));
    }
}