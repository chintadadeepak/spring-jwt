package com.deepak.spring_security.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @RequestMapping("")
    public String greet(HttpServletRequest req) {
        return "Hello World " + req.getSession().getId();
    }

    @RequestMapping("about")
    public String about(HttpServletRequest req) {
        return "Java World " + req.getSession().getId();
    }
}
