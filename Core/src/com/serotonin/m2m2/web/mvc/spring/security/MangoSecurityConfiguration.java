/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.spring.security;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.module.ModuleRegistry;
import com.serotonin.m2m2.module.UriMappingDefinition;
import com.serotonin.m2m2.web.mvc.spring.authentication.MangoUserAuthenticationProvider;
import com.serotonin.m2m2.web.mvc.spring.authentication.MangoUserDetailsService;
import com.serotonin.m2m2.web.mvc.spring.components.JwtService;

/**
 * Spring Security Setup for REST based requests 
 * 
 * @author Terry Packer
 *
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MangoSecurityConfiguration extends WebSecurityConfigurerAdapter {
	//private static final Log LOG = LogFactory.getLog(MangoSecurityConfiguration.class);

    @Autowired
    public void configureAuthenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
        auth.authenticationProvider(authenticationProvider());
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        return new MangoUserDetailsService();
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new MangoUserAuthenticationProvider();
    }

    private static CsrfTokenRepository csrfTokenRepository() {
          HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
          repository.setHeaderName("X-XSRF-TOKEN");
          return repository;
    }

    @Configuration
    @Order(1)
    public static class RestSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Autowired
        private JwtService jwtService;
        
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/rest/**")
                // TODO session cookies are still being set, must be generated elsewhere
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                    .and()
                .formLogin()
                    .disable()
                .logout()
                    .disable()
                .rememberMe()
                    .disable()
                .authorizeRequests()
                    .antMatchers(HttpMethod.GET, "/rest/v1/login/**").permitAll()
                    .antMatchers(HttpMethod.GET, "/rest/v1/translations/public/**").permitAll() //For public translations
                    .antMatchers(HttpMethod.POST, "/v1/jwt").permitAll()
                    .antMatchers(HttpMethod.OPTIONS).permitAll()
                    .anyRequest().authenticated()
                    .anyRequest().permitAll()
                    .and()
                //CSRF Headers https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii
                .addFilterAfter(new CsrfHeaderFilter(), CsrfFilter.class)
                .csrf()
                    //.csrfTokenRepository(csrfTokenRepository())
                    //.and()
                    .disable()
                .headers()
                    .frameOptions().sameOrigin()
                    .and()
                .exceptionHandling()
                    .and()
                .addFilterBefore(new AuthenticationTokenFilter(jwtService), BasicAuthenticationFilter.class);
                //.addFilterBefore(new CorsFilter(), HeaderWriterFilter.class);
        }
    }
    
    @Configuration
    @Order(2)
    public static class DefaultSecurityConfiguration extends WebSecurityConfigurerAdapter {

        private void addModulePermisisons(HttpSecurity http) throws Exception {
            Map<String, String[]> pathToPermission = new HashMap<>();

            for (UriMappingDefinition uriDef : ModuleRegistry.getDefinitions(UriMappingDefinition.class)) {
                if (uriDef.getPath() == null) continue;
                String[] requiredPermissions = uriDef.requirePermissions();
                // TODO check for null, add admin to all?
                pathToPermission.put(uriDef.getPath(), requiredPermissions);
            }

            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authReq = http.authorizeRequests();
            for (Entry<String, String[]> entry : pathToPermission.entrySet()) {
                String path = entry.getKey();
                authReq.antMatchers(path).hasAnyAuthority(entry.getValue());
            }
        }

        @Bean
        public AccessDeniedHandler accessDeniedHandler() {
            return new MangoAccessDeniedHandler();
        }
        
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
            .formLogin()
                .loginPage("/test-login")
                .permitAll()
                .and()
            .logout()
                .invalidateHttpSession(true)
                .deleteCookies("XSRF-TOKEN","MANGO" + Common.envProps.getInt("web.port", 8080))
                .and()
            .rememberMe()
                .and()
            .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/login.htm").permitAll()
                .antMatchers(HttpMethod.POST, "/login.htm").permitAll()
                .antMatchers(HttpMethod.GET, "/" + Common.getVersion() + "/resources/**").permitAll()
                .antMatchers(HttpMethod.GET, "/" + Common.getVersion() + "/dwr/**").permitAll()
                .antMatchers(HttpMethod.GET, "/resources/**").permitAll()
                .antMatchers(HttpMethod.GET, "/images/**").permitAll()
                .antMatchers(HttpMethod.GET, "/audio/**").permitAll()
                .antMatchers(HttpMethod.GET, "/swagger/**").permitAll()
                .antMatchers(HttpMethod.GET, "/exception/*").permitAll()
                .antMatchers(HttpMethod.GET, "/*").permitAll()
                //Allow Startup REST Endpoint
                .antMatchers(HttpMethod.GET, "/status").permitAll()
                // OPTIONS should be allowed on all
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                // dont allow access to any modules folders other than web
                .antMatchers(HttpMethod.GET, "/modules/*/web/**").permitAll()
                .antMatchers("/modules/**").denyAll()
                // deny direct access to jsp
                .antMatchers("*.jsp").denyAll()
                .anyRequest().authenticated()
                .anyRequest().permitAll()
                .and()
                
            //CSRF Headers https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii
            .addFilterAfter(new CsrfHeaderFilter(), CsrfFilter.class)
            .csrf()
                //.csrfTokenRepository(csrfTokenRepository())
                //.and()
                .disable()
            .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
            //Customize the headers here
            .headers()
                .frameOptions().sameOrigin()
                .and();
            
            addModulePermisisons(http);
        }
    }
}
