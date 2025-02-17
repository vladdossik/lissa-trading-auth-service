package lissa.trading.auth.service.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("API для управления авторизацией пользователей")
                        .description("Этот API предоставляет методы для управления авторизацией: регистрация пользователя, аутентификация пользователя, продление JWT токена.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Belaquaa")
                                .url("https://t.me/belaquaa"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://springdoc.org")))
                .components(new Components()
                                    .addSecuritySchemes("bearer-key", new SecurityScheme()
                                            .type(SecurityScheme.Type.HTTP)
                                            .scheme("bearer")
                                            .bearerFormat("JWT"))
                                    .addSecuritySchemes("token-key", new SecurityScheme()
                                            .type(SecurityScheme.Type.APIKEY)
                                            .in(SecurityScheme.In.HEADER)
                                            .name("Authorization")));
    }

    @Bean
    public GroupedOpenApi userApi() {
        return GroupedOpenApi.builder()
                .group("auth")
                .pathsToMatch("/v1/auth/**")
                .addOpenApiCustomizer(openApi -> openApi
                        .addSecurityItem(new SecurityRequirement().addList("bearer-key")))
                .build();
    }

    @Bean
    public GroupedOpenApi internalApi() {
        return GroupedOpenApi.builder()
                .group("internal")
                .pathsToMatch("/v1/internal/**")
                .addOpenApiCustomizer(openApi -> openApi
                        .addSecurityItem(new SecurityRequirement().addList("token-key")))
                .build();
    }
}