package com.benayed.app.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// BasicAuthenticationFilter is a filter parsing the header "Authorization : Basic encoded64base(username:password)"
// To replace it, we extend it then do our stuff without forgetting to add addFilter(new JWTAuthenticationFilter2(authenticationManager())) in the conf class
public class JWTAuthenticationFilter2 extends BasicAuthenticationFilter {
	
	public JWTAuthenticationFilter2(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//Yes this doesn't create a jwt, flemme...
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		Authentication auth = getAuthenticationManager().authenticate(token);
		SecurityContextHolder.getContext().setAuthentication(auth);
		chain.doFilter(request, response);

	}
}
