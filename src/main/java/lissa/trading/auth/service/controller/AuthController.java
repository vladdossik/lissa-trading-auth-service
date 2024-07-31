package lissa.trading.auth.service.controller;

import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.payload.response.MessageResponse;
import lissa.trading.auth.service.service.UserServiceImpl;
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
public class AuthController {

    private final UserServiceImpl userService;

    @PostMapping("/signin")
    public JwtResponse authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.authenticateUser(loginRequest);
    }

    @PostMapping("/signup")
    public MessageResponse registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        userService.registerUser(signUpRequest);
        return new MessageResponse("User registered successfully");
    }
}