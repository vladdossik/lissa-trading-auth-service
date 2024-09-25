package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.request.UserInfoRequestDto;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth.service.service.user.UserService;
import lissa.trading.lissa.auth.lib.dto.UserInfoDto;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/v1/internal")
@RequiredArgsConstructor
@Tag(name = "Internal Token Controller", description = "API для внутренних запросов")
public class InternalController {

    private final UserService userService;

    @Operation(summary = "[internal] Проверка внутреннего токена")
    @ApiResponse(
            description = "Внутренний токен работает правильно",
            content = @Content(schema = @Schema(implementation = String.class))
    )
    @PostMapping("/test")
    public String testInternalToken() {
        return "Internal token works properly";
    }

    @Operation(summary = "[internal] Регистрация нового пользователя")
    @ApiResponse(
            description = "Пользователь успешно зарегистрирован",
            content = @Content(schema = @Schema(implementation = UserRegistrationResponse.class))
    )
    @PostMapping("/signup")
    public UserRegistrationResponse registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }

    @Operation(summary = "[internal] Получение информации о пользователе из JWT токена. Для неавторизованных пользователей возвращается пустой объект")
    @ApiResponse(
            description = "Информация о пользователе успешно получена",
            content = @Content(schema = @Schema(implementation = UserInfoDto.class))
    )
    @PostMapping("/user-info")
    public UserInfoDto getUserInfo(@RequestBody UserInfoRequestDto request) {
        return userService.getUserByTelegramNickname(request.getTelegramNickname());
    }
}