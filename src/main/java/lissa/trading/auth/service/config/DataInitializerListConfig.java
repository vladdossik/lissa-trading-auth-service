package lissa.trading.auth.service.config;

import lissa.trading.auth.service.service.dataInitializer.DataInitializerService;
import lissa.trading.auth.service.service.dataInitializer.UserInitializerService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.List;

@Configuration
@RequiredArgsConstructor
@Profile("local")
public class DataInitializerListConfig {

    private final UserInitializerService userInitializerService;

    @Bean
    public List<DataInitializerService> dataInitializerServices() {
        return List.of(userInitializerService);
    }
}
