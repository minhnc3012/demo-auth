package com.example.demo;

import java.util.function.Function;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.factory.TokenRelayGatewayFilterFactory;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.route.builder.UriSpec;
import org.springframework.context.annotation.Bean;

import com.example.demo.configuration.TokenRelayGatewayAddXTenantHeaderFilterFactory;

@SpringBootApplication
public class DemoAuthClientApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(DemoAuthClientApplication.class, args);
	}

	@Bean
    RouteLocator gateway(RouteLocatorBuilder builder, TokenRelayGatewayAddXTenantHeaderFilterFactory filterFactory) {
        return builder
                .routes()
                .route("service-one", rs -> rs
                        .path("/service-one/api/**")
                        // .filters(f -> f.tokenRelay("public-client-oidc"))  // Ensure tokenRelay is used here
                        .filters(f -> f.filter(filterFactory.apply(c -> c.setName("public-client-oidc"))))
                        .uri("http://localhost:8081"))
                
                .build();
    }
}
