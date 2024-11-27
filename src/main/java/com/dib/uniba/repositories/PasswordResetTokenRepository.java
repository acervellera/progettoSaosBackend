package com.dib.uniba.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dib.uniba.entities.PasswordResetToken;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
}
