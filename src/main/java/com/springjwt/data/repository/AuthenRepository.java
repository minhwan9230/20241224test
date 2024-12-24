package com.springjwt.data.repository;

import com.springjwt.data.entity.AuthenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthenRepository extends JpaRepository<AuthenEntity, Integer> {
    AuthenEntity findByUsername(String username);
    Boolean existsByUsername(String username);
}
