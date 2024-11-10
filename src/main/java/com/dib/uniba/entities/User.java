package com.dib.uniba.entities;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.Data;
import lombok.experimental.Accessors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;
import java.util.List;

@Data
@Entity
@Accessors(chain = true) // Abilita i setter fluenti
@Table(name = "users")
public class User implements UserDetails {

    private static final long serialVersionUID = 6338360474060585841L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(nullable = false,unique = true)
    private Integer id;

    @Column(nullable = false)
    private String fullName;

    @Column(unique = true, length = 100, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @CreationTimestamp
    @Column(updatable = false, name = "created_at")
    private Date createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Date updatedAt;
    
    @Column(nullable = false)
    private String role;

    // Implementazione di UserDetails per Spring Security
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role)); // Fornisce l'autorità basata sul ruolo dell'utente
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
