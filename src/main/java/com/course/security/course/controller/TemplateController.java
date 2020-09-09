package com.course.security.course.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public ModelAndView loginView(){
        return new ModelAndView("login");
    }

    @GetMapping("/courses")
    public ModelAndView coursesView(){
        return new ModelAndView("courses");
    }
}
