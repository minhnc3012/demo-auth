package com.example.demo.configuration;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
          .oidc(withDefaults()); // Enable OpenID Connect 1.0
        return http.formLogin(withDefaults()).build();
    }
	
	@Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> 
                authz
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults())	     
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));
        return http.build();
    }
	
	@Bean
    public JdbcUserDetailsManager userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }
    
    @Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}
	/*
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityChain(HttpSecurity httpSecurity, RegisteredClientRepository registeredClientRepository) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .clientAuthentication(authentication -> {
                    authentication.authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter());
                    authentication.authenticationProvider(new PublicClientRefreshProvider(registeredClientRepository));
                })
                .tokenGenerator(tokenGenerator())
                .oidc(Customizer.withDefaults()); // enable open id connect 1.0

        httpSecurity.exceptionHandling(exception -> {
            exception.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher((MediaType.TEXT_HTML))
            );
        });

        httpSecurity.oauth2ResourceServer(server -> {
            server.jwt(Customizer.withDefaults());
        });

        return httpSecurity.build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(
                authorize -> authorize.anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    @Bean
    public JdbcUserDetailsManager userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRSAKeys();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey build = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(build);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRSAKeys() {
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception exception) {
            throw  new RuntimeException("failed to create keypair!");
        }

        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
        return context -> {
            if(context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                Authentication principle = context.getPrincipal();
                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority authority: principle.getAuthorities()) {
                    authorities.add(authority.getAuthority());
                }

                context.getClaims().claim("authorities", authorities);
            }
        };
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator() {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
        jwtGenerator.setJwtCustomizer(customizer());
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenOAuth2TokenGenerator = new CustomOAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenOAuth2TokenGenerator);
    }

    public final class CustomOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
        private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

        public CustomOAuth2RefreshTokenGenerator() {
        }

        @Nullable
        public OAuth2RefreshToken generate(OAuth2TokenContext context) {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }  else {
                Instant issuedAt = Instant.now();
                Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
                return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
            }
        }
    }

    private static final class PublicClientRefreshTokenAuthentication extends OAuth2ClientAuthenticationToken {

        public PublicClientRefreshTokenAuthentication(String clientId) {
            super(clientId, ClientAuthenticationMethod.NONE, null, null);
        }

        public PublicClientRefreshTokenAuthentication(RegisteredClient registeredClient) {
            super(registeredClient, ClientAuthenticationMethod.NONE, null);
        }
    }

    private static final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

        @Override
        public Authentication convert(HttpServletRequest request) {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            if(!grantType.equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
                return null;
            }

            String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
            if(!StringUtils.hasText(clientId)) {
                return null;
            }

            return new PublicClientRefreshTokenAuthentication(clientId);
        }
    }

    private static final class PublicClientRefreshProvider implements AuthenticationProvider {
        private final RegisteredClientRepository registeredClientRepository;

        private PublicClientRefreshProvider(RegisteredClientRepository registeredClientRepository) {
            this.registeredClientRepository = registeredClientRepository;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            PublicClientRefreshTokenAuthentication publicClientRefreshTokenAuthentication = (PublicClientRefreshTokenAuthentication) authentication;

            if(!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(publicClientRefreshTokenAuthentication.getClientAuthenticationMethod())) {
                return null;
            }

            String clientId = publicClientRefreshTokenAuthentication.getPrincipal().toString();
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

            if(registeredClient == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_CLIENT,
                        "client is not valid",
                        null
                ));
            }

            if(!registeredClient.getClientAuthenticationMethods().contains(
                    publicClientRefreshTokenAuthentication.getClientAuthenticationMethod()
            )) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_CLIENT,
                        "authentication_method is not register with client",
                        null
                ));
            }
            return new PublicClientRefreshTokenAuthentication(registeredClient);
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return PublicClientRefreshTokenAuthentication.class.isAssignableFrom(authentication);
        }
    }
    */
}
