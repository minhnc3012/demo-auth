package com.example.demo.configuration.data;

import java.util.Objects;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class InitDataConfiguration {
	@Bean
	public ApplicationRunner applicationRunner(RegisteredClientRepository registeredClientRepository,
			UserDetailsManager userDetailsManager) {
		return args -> {
			if (Objects.isNull(registeredClientRepository.findByClientId("public-client"))) {
				registeredClientRepository.save(RegisteredClientBuilder.buildRegisteredClientForPublicClient());
			}

			if (!userDetailsManager.userExists("admin")) {
				UserDetails user = User.withDefaultPasswordEncoder().username("admin").password("123").roles("ADMIN")
						.build();

				userDetailsManager.createUser(user);
			}

			if (!userDetailsManager.userExists("user")) {
				UserDetails user = User.withDefaultPasswordEncoder().username("user").password("123").roles("USER")
						.build();

				userDetailsManager.createUser(user);
			}

		};
	}
}
