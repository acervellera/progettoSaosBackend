package com.dib.uniba.services;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final Map<String, String> temporaryTokens = new ConcurrentHashMap<>();

    public String generateTemporaryToken(String email) {
        String token = UUID.randomUUID().toString();
        temporaryTokens.put(email, token);
        return token;
    }

    public boolean isTemporaryTokenValid(String email, String token) {
        return token != null && token.equals(temporaryTokens.get(email));
    }

    public void invalidateTemporaryToken(String email) {
        temporaryTokens.remove(email);
    }
}
