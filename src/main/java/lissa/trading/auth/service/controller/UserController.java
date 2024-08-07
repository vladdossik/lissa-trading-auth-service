package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth.service.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "User Registration Controller", description = "API для регистрации пользователей")
public class UserController {

    private final UserService userService;

    @Operation(summary = "Регистрация нового пользователя")
    @PostMapping("/signup")
    public UserRegistrationResponse registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }
}