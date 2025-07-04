package com.devteria.identityservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.devteria.identityservice.entity.InvalidatedToken;

public interface InvalidatedTokenRepository  extends JpaRepository<InvalidatedToken, String>{
    
}
