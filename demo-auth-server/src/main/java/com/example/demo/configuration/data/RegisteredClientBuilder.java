package com.example.demo.configuration.data;

import java.util.UUID;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

public class RegisteredClientBuilder {

    public static RegisteredClient buildRegisteredClientForPublicClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("public-client")
            .clientSecret("{noop}secret") // For simple demonstration only; use a hashed secret in production
            .clientName("Public Client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://kerb.localhost:8080/login/oauth2/code/public-client-oidc")
            .redirectUri("http://kerb.localhost:8080/authorized")
            .scope("client.read").scope("client.write")
            .scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();
    }
}

