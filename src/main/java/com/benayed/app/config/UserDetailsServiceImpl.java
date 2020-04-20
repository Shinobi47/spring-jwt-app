package com.benayed.app.config;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{
	
	private List<UserDetails> users;
	
	PasswordEncoder encoder = new BCryptPasswordEncoder();
	
	public UserDetailsServiceImpl() {
		
	}

	private void initUsers() {
		UserDetails user1 = User.builder().username("Haytam").password(encoder.encode("123456")).authorities("ROOT").build();
		UserDetails user2 = User.builder().username("User1").password(encoder.encode("123456")).authorities("USER").build();
		UserDetails user3 = User.builder().username("Guignaoui").password(encoder.encode("123456")).authorities("ROOT, USER").build();

		users = Arrays.asList(user1, user2, user3);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		initUsers();
		Optional<UserDetails> user = users.stream().filter(userNameExists(username)).findFirst();
		return user.orElseThrow(() -> new UsernameNotFoundException("user not found !"));
	}

	private Predicate<? super UserDetails> userNameExists(String username) {
		return u -> u.getUsername().equals(username);
	}
	
	

}
