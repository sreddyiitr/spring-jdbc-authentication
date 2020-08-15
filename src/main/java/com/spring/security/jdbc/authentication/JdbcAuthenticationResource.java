package com.spring.security.jdbc.authentication;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JdbcAuthenticationResource {

	@GetMapping("/")
	public String home() {
		return "<h1>Welcome to the homeland</h1>";
	}
	
	@GetMapping("/user")
	public String user() {
		return "<h1>Welcome to the User page</h1>";
	}

	@GetMapping("/admin")
	public String admin() {
		return "<h1>Welcome to the Admin page</h1>";
	}

}
