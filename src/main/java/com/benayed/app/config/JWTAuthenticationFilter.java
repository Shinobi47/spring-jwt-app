package com.benayed.app.config;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @author Kenji
 *
 */

//We have extended the BasicAuthenticationFilter to make Spring replace it in the filter chain with our custom implementation
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter { // extends BasicAuthenticationFilter{
	
	private AuthenticationManager authenticationManager;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {

		this.authenticationManager = authenticationManager;
	}
	
	
	@Override 
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		//Request made by spring default login page : curl -i -X POST -d 'username=Haytam&password=123456' -L = "http://localhost:8080/login"
		String username = request.getParameter("username");
		String password = request.getParameter("password");;
		try {


		} catch ( Exception e) {
			throw new RuntimeException(e);
		}
		return this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}
	
	@Override
		protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		User user = (User) authResult.getPrincipal();
		
		String jwtToken = Jwts.builder()
				.setSubject(user.getUsername())
				.setExpiration(new Date(System.currentTimeMillis() + 300000))
				.signWith(SignatureAlgorithm.HS256, "secret")
				.claim("authorities", user.getAuthorities())
				.compact();
		response.addHeader("Authorization", "Bearer " + jwtToken);
	
	}

}

// in case of a JSON post request
//ObjectNode node =  new ObjectMapper().readValue(request.getInputStream(), ObjectNode.class);
//username = node.get("username").asText();
//password = node.get("password").asText();
