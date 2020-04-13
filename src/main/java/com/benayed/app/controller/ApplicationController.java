package com.benayed.app.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController {

	@GetMapping(path = "/hello")
	public String hello() {
		return "Hello Haytam, you look great today !";
	}
}
