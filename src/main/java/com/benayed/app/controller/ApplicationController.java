package com.benayed.app.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController {

	@GetMapping(path = "/hello")
	public String hello() {
		return "Hello Haytam, you look great today !";
	}
	
	@PreAuthorize("hasAuthority('ROOT')")
	@GetMapping(path = "/auth-hello")
	public String authHello() {
		return "Hello Haytam, you look great today ! and this is an authentified method";
	}
}
