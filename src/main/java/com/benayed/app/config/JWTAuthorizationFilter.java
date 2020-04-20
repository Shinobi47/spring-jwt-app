package com.benayed.app.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		response.addHeader("Access-Control-Allow-Origin", "*");
		response.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization");
		response.addHeader("Access-Control-Expose-Headers", "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Authorization");
		if(request.getMethod().equals("OPTIONS")) {
			response.setStatus(HttpServletResponse.SC_OK);
		}

		else {
			String authorizationHeaderValue = request.getHeader("Authorization");
			if(StringUtils.isEmpty(authorizationHeaderValue) || !authorizationHeaderValue.startsWith("Bearer ")) {
				filterChain.doFilter(request, response); // Causes the next filter in the chain to be invoked
				return;
			}

			Claims claims = Jwts.parser()
					.setSigningKey("secret")
					.parseClaimsJws(authorizationHeaderValue.replace("Bearer ","")) // signature checked here
					.getBody();
			String username = claims.getSubject();
			ArrayList<Map<String, String>> authoritiesClaim = (ArrayList<Map<String, String>>)claims.get("authorities");
			Collection<GrantedAuthority> authorities = authoritiesClaim.stream()
					.map(map -> new SimpleGrantedAuthority(map.get("authority")))
					.collect(Collectors.toList());
			
			SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, authorities));
			
			filterChain.doFilter(request, response);
		}


	}

}
