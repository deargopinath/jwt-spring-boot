package com.gopinath.token.issuer.controller;

import com.gopinath.token.issuer.model.RequestData;
import com.gopinath.token.issuer.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.validation.Valid;

import java.util.stream.Collectors;

@RestController
public class TokenController {

    @Autowired
    TokenService tokenService;

    private final Logger LOG = LoggerFactory.getLogger(TokenController.class);

    @PostMapping("/api/jwe")
    public ResponseEntity<?> getToken(@Valid @RequestBody final RequestData requestData, final Errors errors) {

        if (errors.hasErrors()) {
            String errorMessage = errors.getAllErrors().stream().map(x -> x.getDefaultMessage()).collect(Collectors.joining(","));
            LOG.error("Error = " + errorMessage);
            return ResponseEntity.badRequest().body(errorMessage);
        }
        String subject = requestData.getSubject();
        String jwe = tokenService.getToken(requestData);
        String json = ("{\"subject\":\"" + subject 
                + "\",\"token\":\"" + jwe + "\"}");
        LOG.info("Token generated for " + subject);
        final HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwe);
        LOG.info("Authorization Header set with token");
        return (new ResponseEntity<>(json, headers, HttpStatus.OK));
    }
}
