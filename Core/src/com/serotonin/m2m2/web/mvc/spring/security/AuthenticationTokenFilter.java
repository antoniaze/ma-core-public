package com.serotonin.m2m2.web.mvc.spring.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.web.mvc.spring.authentication.MangoUserDetailsService;
import com.serotonin.m2m2.web.mvc.spring.components.JwtService;

/**
 * Authenticates a user based on an API token
 * 
 * @author Jared Wiltshire
 *
 */
public class AuthenticationTokenFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public AuthenticationTokenFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        
        String token = header.substring(7);

        Jws<Claims> claims;
        // decode
        try {
            claims = jwtService.parseToken(token);
        } catch (Exception e) {
            chain.doFilter(request, response);
            return;
        }
        
        String username = claims.getBody().getSubject();
        
        // TODO check if this is needed or expired exception thrown above
        Date expiry = claims.getBody().getExpiration();
        if (username == null || expiry == null || expiry.getTime() <= System.currentTimeMillis()) {
            chain.doFilter(request, response);
            return;
        }
        
        if (authenticationIsRequired(username)) {
            User user = UserDao.instance.getUser(username);
            Common.setUser(request, user);

            List<GrantedAuthority> authorities = MangoUserDetailsService.generateGrantedAuthorities(user);

            PreAuthenticatedAuthenticationToken auth = new PreAuthenticatedAuthenticationToken(user, claims, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }
    
    private boolean authenticationIsRequired(String username) {
        // Only reauthenticate if username doesn't match SecurityContextHolder and user
        // isn't authenticated
        // (see SEC-53)
        Authentication existingAuth = SecurityContextHolder.getContext()
                .getAuthentication();

        if (existingAuth == null || !existingAuth.isAuthenticated()) {
            return true;
        }

        // Limit username comparison to providers which use usernames (ie
        // UsernamePasswordAuthenticationToken)
        // (see SEC-348)

        if (existingAuth instanceof UsernamePasswordAuthenticationToken
                && !existingAuth.getName().equals(username)) {
            return true;
        }

        // Handle unusual condition where an AnonymousAuthenticationToken is already
        // present
        // This shouldn't happen very often, as BasicProcessingFitler is meant to be
        // earlier in the filter
        // chain than AnonymousAuthenticationFilter. Nevertheless, presence of both an
        // AnonymousAuthenticationToken
        // together with a BASIC authentication request header should indicate
        // reauthentication using the
        // BASIC protocol is desirable. This behaviour is also consistent with that
        // provided by form and digest,
        // both of which force re-authentication if the respective header is detected (and
        // in doing so replace
        // any existing AnonymousAuthenticationToken). See SEC-610.
        if (existingAuth instanceof AnonymousAuthenticationToken) {
            return true;
        }

        return false;
    }
}
