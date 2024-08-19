package lissa.trading.auth.service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lissa.trading.auth.service.dto.UserInfoDto;
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

    @Operation(summary = "Получение информации о пользователе из токена. Для неавторизованных пользователей возвращается пустой объект")
    @ApiResponse(
            description = "Информация о пользователе успешно получена",
            content = @Content(schema = @Schema(implementation = UserInfoDto.class))
    )
    @PostMapping("/user-info")
    public UserInfoDto getUserInfo(@RequestHeader("Authorization") String token) {
        if (!jwtService.validateJwtToken(token)) {
            return null;
        }
        return jwtService.getUserInfoFromJwtToken(token);
    }
}