package com.example.demo.web.rest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/gateway/api")
public class HomeController {

	@GetMapping("/index")
	public String index() {
		return SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
	}
}
