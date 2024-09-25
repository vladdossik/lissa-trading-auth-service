package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth.service.service.user.UserService;
import jakarta.validation.Valid;
import lissa.trading.lissa.auth.lib.dto.UserInfoDto;
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
@Tag(name = "User Controller", description = "API для взаимодействия с пользователями")
public class UserController {

    private final UserService userService;

    @Operation(summary = "Регистрация нового пользователя")
    @ApiResponse(
            description = "Пользователь успешно зарегистрирован",
            content = @Content(schema = @Schema(implementation = UserRegistrationResponse.class))
    )
    @PostMapping("/signup")
    public UserRegistrationResponse registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }

    @Operation(summary = "Получение информации о пользователе из JWT токена. Для неавторизованных пользователей возвращается пустой объект")
    @ApiResponse(
            description = "Информация о пользователе успешно получена",
            content = @Content(schema = @Schema(implementation = UserInfoDto.class))
    )
    @PostMapping("/user-info")
    public UserInfoDto getUserInfo() {
        return userService.getUserInfoFromContext();
    }
}