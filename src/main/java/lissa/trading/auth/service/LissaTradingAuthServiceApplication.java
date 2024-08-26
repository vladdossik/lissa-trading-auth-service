package lissa.trading.auth.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "lissa.trading")
public class LissaTradingAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(LissaTradingAuthServiceApplication.class, args);
    }

}
