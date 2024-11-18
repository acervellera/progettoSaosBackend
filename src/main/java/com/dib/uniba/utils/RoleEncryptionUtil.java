package com.dib.uniba.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Classe utility per la cifratura e decifratura dei ruoli utilizzando la crittografia AES.
 * <p>
 * Questa utility utilizza l'algoritmo di crittografia AES per trasformare in modo sicuro
 * i ruoli in un formato cifrato e decifrarli quando necessario.
 * La chiave di crittografia viene caricata dal file di configurazione dell'applicazione.
 * </p>
 */
@Component
public class RoleEncryptionUtil {

    private static final String ALGORITHM = "AES"; // L'algoritmo di crittografia utilizzato
    private final SecretKeySpec keySpec; // Specifica della chiave segreta per AES

    /**
     * Costruttore per inizializzare la chiave di crittografia.
     * <p>
     * La chiave viene fornita come stringa codificata in base64 dal file di configurazione
     * dell'applicazione, decodificata e utilizzata per creare la specifica della chiave segreta.
     * </p>
     *
     * @param secretKey la chiave di crittografia codificata in base64, caricata dalle proprietà dell'applicazione
     */
    public RoleEncryptionUtil(@Value("${security.encryption.key}") String secretKey) {
        // Decodifica della chiave codificata in base64
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        // Creazione di un oggetto SecretKeySpec utilizzando la chiave decodificata e l'algoritmo AES
        this.keySpec = new SecretKeySpec(decodedKey, ALGORITHM);
    }

    /**
     * Cifra un ruolo fornito.
     * <p>
     * Converte una stringa di ruolo in formato testo chiaro in un formato cifrato utilizzando
     * l'algoritmo AES e codifica i dati cifrati in una stringa codificata in base64.
     * </p>
     *
     * @param role il ruolo in chiaro da cifrare
     * @return una stringa cifrata codificata in base64
     * @throws Exception se si verifica un errore durante la cifratura
     */
    public String encryptRole(String role) throws Exception {
        // Creazione e inizializzazione di un'istanza di Cipher per la cifratura
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        // Cifra il ruolo e restituisce una stringa codificata in base64
        byte[] encryptedBytes = cipher.doFinal(role.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decifra un ruolo cifrato.
     * <p>
     * Converte una stringa cifrata codificata in base64 nel suo ruolo in chiaro utilizzando
     * l'algoritmo AES.
     * </p>
     *
     * @param encryptedRole il ruolo cifrato codificato in base64 da decifrare
     * @return il ruolo in chiaro
     * @throws Exception se si verifica un errore durante la decifratura
     */
    public String decryptRole(String encryptedRole) throws Exception {
        // Creazione e inizializzazione di un'istanza di Cipher per la decifratura
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        // Decodifica la stringa codificata in base64 e la decifra
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedRole);
        return new String(cipher.doFinal(decodedBytes));
    }
}
