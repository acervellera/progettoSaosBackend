package com.dib.uniba.responses;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true) // Abilita i setter fluenti
public class LoginResponse {
    private String token;

    private long expiresIn;

    public String getToken() {
        return token;
    }

 // Getters and setters...
}