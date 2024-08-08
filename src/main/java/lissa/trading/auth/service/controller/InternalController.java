package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lissa.trading.auth.service.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Internal Token Validation Controller", description = "API для валидации токена")
public class InternalController {

    private final JwtService jwtService;

    @Operation(summary = "Валидация токена")
    @PostMapping("/validate")
    public boolean validateToken(@RequestHeader("Authorization") String token) {
        return jwtService.validateJwtToken(token.startsWith("Bearer ") ? token.substring(7) : token);
    }
}