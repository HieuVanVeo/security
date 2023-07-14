package com.example.demo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/user")
    @Secured("USER")
    public String helloUser() {
        return "Hello user Nashtech";
    }

    @GetMapping("/admin")
    @Secured("hasRole('ADMIN')")
    public String helloAdmin() {
        return "Hello admin Nashtech";
    }
}
