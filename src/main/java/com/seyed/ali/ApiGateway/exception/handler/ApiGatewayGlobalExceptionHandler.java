package com.seyed.ali.ApiGateway.exception.handler;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.reactive.function.client.WebClientResponseException;

@RestControllerAdvice
public class ApiGatewayGlobalExceptionHandler {

    @ExceptionHandler(WebClientResponseException.ServiceUnavailable.class)
    public ResponseEntity<?> handleWebClientResponseExceptionServiceUnavailable(WebClientResponseException.ServiceUnavailable ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
    }

}
