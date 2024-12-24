package com.springjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping(value="/")
    public String home() {
        return "Main Controller";
    }
}
