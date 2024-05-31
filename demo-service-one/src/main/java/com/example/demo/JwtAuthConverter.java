package com.example.demo;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;

public class JwtAuthConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public JwtAuthConverter() {
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        //jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
    	Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
        System.out.println("Authorities: " + authorities); // Log the authorities to check
        return authorities;
        // return jwtGrantedAuthoritiesConverter.convert(jwt);
    }
}

