package com.example.demo.configuration;


import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class TokenRelayGatewayAddXTenantHeaderFilterFactory
		extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {

	private static final String TENANT_HEADER = "X-TenantId";
	private final ObjectProvider<ReactiveOAuth2AuthorizedClientManager> clientManagerProvider;

	public TokenRelayGatewayAddXTenantHeaderFilterFactory(ObjectProvider<ReactiveOAuth2AuthorizedClientManager> clientManagerProvider) {
		super(NameConfig.class);
		this.clientManagerProvider = clientManagerProvider;
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return Collections.singletonList(NAME_KEY);
	}

	public GatewayFilter apply() {
		return apply((NameConfig) null);
	}

	@Override
	public GatewayFilter apply(NameConfig config) {
		String defaultClientRegistrationId = (config == null) ? null : config.getName();
		return (exchange, chain) -> exchange.getPrincipal()
				// .log("token-relay-filter")
				.filter(principal -> principal instanceof Authentication).cast(Authentication.class)
				.flatMap(principal -> authorizationRequest(defaultClientRegistrationId, principal))
				.flatMap(this::authorizedClient).map(OAuth2AuthorizedClient::getAccessToken)
				.map(token -> withBearerAuth(exchange, token))
				.map(token -> withXTenentId(exchange, chain))
				// TODO: adjustable behavior if empty
				.defaultIfEmpty(exchange).flatMap(chain::filter);
	}

	private ServerWebExchange withXTenentId(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		// Determine subdomain from request
        String subdomain = extractSubdomain(request.getURI().getHost());
//        // Create a new request with the tenant header
//        ServerHttpRequest modifiedRequest = request.mutate()
//                .header(TENANT_HEADER, subdomain)
//                .build();
//
//        ServerWebExchange modifiedExchange = exchange.mutate().request(modifiedRequest).build();
        return exchange.mutate().request(r -> r.headers(headers -> headers.addIfAbsent(TENANT_HEADER, subdomain)))
				.build();
	}

	private Mono<OAuth2AuthorizeRequest> authorizationRequest(String defaultClientRegistrationId,
			Authentication principal) {
		String clientRegistrationId = defaultClientRegistrationId;
		if (clientRegistrationId == null && principal instanceof OAuth2AuthenticationToken) {
			clientRegistrationId = ((OAuth2AuthenticationToken) principal).getAuthorizedClientRegistrationId();
		}
		return Mono.justOrEmpty(clientRegistrationId).map(OAuth2AuthorizeRequest::withClientRegistrationId)
				.map(builder -> builder.principal(principal).build());
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(OAuth2AuthorizeRequest request) {
		ReactiveOAuth2AuthorizedClientManager clientManager = clientManagerProvider.getIfAvailable();
		if (clientManager == null) {
			return Mono.error(new IllegalStateException(
					"No ReactiveOAuth2AuthorizedClientManager bean was found. Did you include the "
							+ "org.springframework.boot:spring-boot-starter-oauth2-client dependency?"));
		}
		// TODO: use Mono.defer() for request above?
		return clientManager.authorize(request);
	}

	private ServerWebExchange withBearerAuth(ServerWebExchange exchange, OAuth2AccessToken accessToken) {
		return exchange.mutate().request(r -> r.headers(headers -> headers.setBearerAuth(accessToken.getTokenValue())))
				.build();
	}
	
	private String extractSubdomain(String host) {
        if (host == null || !host.contains(".")) {
            return null;
        }
        return host.substring(0, host.indexOf("."));
    }
}
