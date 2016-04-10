package com.serotonin.m2m2.web.mvc.spring.security;

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.eclipse.jetty.servlets.CrossOriginFilter;

public class CorsFilter extends CrossOriginFilter {

    public CorsFilter() throws ServletException {
        super();
        init(new FilterConfig() {
            @Override
            public String getFilterName() {
                return null;
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                switch(name) {
                case ALLOWED_ORIGINS_PARAM:
                    return "*";
                case ALLOWED_METHODS_PARAM:
                    return "PUT,POST,GET,OPTIONS,DELETE";
                case ALLOWED_HEADERS_PARAM:
                    return "X-Requested-With,Content-Type,Accept,Origin,Authorization";
                }
                return null;
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return null;
            }
            
        });
    }

}
