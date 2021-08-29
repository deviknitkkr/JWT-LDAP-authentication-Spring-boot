package com.devik.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ApiController {

    @GetMapping("/home")
    public String greet(){
        return "Hello world";
    }

    @GetMapping("/sso")
    public Principal getsso(Principal principal){
        return principal;
    }
}
