package com.example.securityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Zhurenkov Pavel 31.03.2024
 */
@Controller
public class MyController {

    @ResponseBody
    @RequestMapping("/ReadBook")
    @PreAuthorize("hasAuthority('book.read')")
    public String hello(){
        return "ADMIN can read books";
    }

    @ResponseBody
    @RequestMapping("/CreateBook")
    @PreAuthorize("hasAuthority('book.create')")
    public String createBook(){
        return "Only ADMIN can read books";
    }
}
