/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.spring.authentication;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.vo.User;

/**
 * Class for plug-in User Access for Authentication Data
 * 
 * @author Terry Packer
 *
 */
public class MangoUserDetailsService implements UserDetailsService {

	/* (non-Javadoc)
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		
		User u = UserDao.instance.getUser(username);
		if(u != null)
			return new MangoUser(u, generateGrantedAuthorities(u));
		
		throw new UsernameNotFoundException(username);
	}
	
	public static List<GrantedAuthority> generateGrantedAuthorities(User user) {
	    String [] roles = user.getPermissions().split(",");
        List<GrantedAuthority> permissions = new ArrayList<GrantedAuthority>(roles.length);

        // TODO check if superadmin and admin should be combined into one role
        boolean adminAdded = false;
        for (String role : roles) {
            role = role.trim().toUpperCase();
            if ("ADMIN".equals(role))
                adminAdded = true;
            permissions.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        
        // dont add twice
        if(user.isAdmin() && !adminAdded)
            permissions.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        
        return permissions;
	}
}
