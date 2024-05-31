package com.example.demo.service;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class GreetingsService {

	@PreAuthorize("hasRole('USER') OR hasRole('ADMIN')")
	public Map<String, String> greet() {
		var jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return Map.of("message", "Hello " + jwt.getSubject());
	}
}
