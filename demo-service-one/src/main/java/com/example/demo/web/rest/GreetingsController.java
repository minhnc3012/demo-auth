package com.example.demo.web.rest;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.example.demo.service.GreetingsService;

@Controller
@ResponseBody
@RequestMapping("/api")
public class GreetingsController {

	private final GreetingsService service;

    GreetingsController(GreetingsService service) {
        this.service = service;
    }
    
	@GetMapping("/hello")
	public Map<String, String> hello() {
		return this.service.greet();
	}
}