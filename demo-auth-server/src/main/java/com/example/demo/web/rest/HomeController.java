package com.example.demo.web.rest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@RequestMapping("/api")
public class HomeController {

	@GetMapping
	public String index() {
		return SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
	}
}
