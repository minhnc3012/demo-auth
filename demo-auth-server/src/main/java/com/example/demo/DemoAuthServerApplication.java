package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@SpringBootApplication
public class DemoAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoAuthServerApplication.class, args);
	}
}
