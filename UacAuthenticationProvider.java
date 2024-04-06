package org.flowable.ui.common.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;

public class UacAuthenticationProvider implements AuthenticationProvider{

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("returning Authentication: " + authentication);
        // TODO: convert the token in the authentication to user details
        // return authentication;

        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();
                
        if (!name.contains("admin") && !name.contains("user")) {
            return null;
        }        
       
        return authenticateAgainstThirdPartyAndGetAuthentication(name, password);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }

    private static UsernamePasswordAuthenticationToken authenticateAgainstThirdPartyAndGetAuthentication(String name, String password) {
        final List<GrantedAuthority> grantedAuths = new ArrayList<>();
        // grantedAuths.add(new SimpleGrantedAuthority("access-idm"));
        // grantedAuths.add(new SimpleGrantedAuthority("access-admin"));
        // grantedAuths.add(new SimpleGrantedAuthority("access-modeler"));
        // grantedAuths.add(new SimpleGrantedAuthority("access-task"));
        // grantedAuths.add(new SimpleGrantedAuthority("access-rest-api"));
        final UserDetails principal = new User(name, password, grantedAuths);
        return new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
    }
}
