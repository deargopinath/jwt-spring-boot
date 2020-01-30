package com.gopinath.service.provider.controller;

import com.gopinath.service.provider.service.TokenValidator;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class HomePageController {
    
    @Autowired
    TokenValidator tokenValidator;
    
    private final Logger LOG = LoggerFactory.getLogger(HomePageController.class);
    
    @GetMapping("/")
    public ResponseEntity<?> index(HttpServletRequest request) {
        
        String output = ("<html><head><title>Service Provider</title></head>"
                + "<body><h1>Error</h1><p>Invalid token</p></body></html>");
        if(tokenValidator.isValid(request)) {            
            String greeting = ("Hello " + tokenValidator.getUser());
            String account = ("Account # " + tokenValidator.getAccount());
            output = output.replaceAll("Error", "Welcome")
                    .replaceAll("Invalid token", greeting + "</p><p>" + account);
        }
        return (new ResponseEntity<>(output, HttpStatus.OK));
    }
}