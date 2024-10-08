package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.TokenRefreshRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.service.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication Controller", description = "API для аутентификации и управления JWT-токеном")
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Аутентификация пользователя")
    @ApiResponse(
            description = "Пользователь успешно аутентифицирован",
            content = @Content(schema = @Schema(implementation = JwtResponse.class))
    )
    @PostMapping("/signin")
    public JwtResponse authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return authService.authenticateUser(loginRequest);
    }

    @Operation(summary = "Обновление токена")
    @ApiResponse(
            description = "Токен успешно обновлен",
            content = @Content(schema = @Schema(implementation = JwtResponse.class))
    )
    @PostMapping("/refresh-token")
    public JwtResponse refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        return authService.refreshToken(request);
    }
}