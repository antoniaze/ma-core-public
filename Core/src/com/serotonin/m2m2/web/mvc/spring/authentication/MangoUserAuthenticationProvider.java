/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.spring.authentication;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.vo.User;

/**
 * @author Terry Packer
 *
 */
public class MangoUserAuthenticationProvider implements AuthenticationProvider{

	/* (non-Javadoc)
	 * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.core.Authentication)
	 */
	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
	    
	    if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            return null;
        }
		
		User user = UserDao.instance.getUser(authentication.getName());
		if(user == null)
			throw new BadCredentialsException(Common.translate("login.validation.invalidLogin"));
		
		if(user.isDisabled())
			throw new DisabledException(Common.translate("login.validation.accountDisabled"));
		
		//Do Login
		user = Common.loginManager.performLogin(authentication.getName(), (String)authentication.getCredentials(), false);
		
		if(user == null)
			throw new BadCredentialsException(Common.translate("login.validation.invalidLogin"));
		
		List<GrantedAuthority> authorities = MangoUserDetailsService.generateGrantedAuthorities(user);

		//Set User object as the Principle in our Token
		return new UsernamePasswordAuthenticationToken(user, user.getPassword(), authorities);
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
	 */
	@Override
	public boolean supports(Class<?> authentication) {
	    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
