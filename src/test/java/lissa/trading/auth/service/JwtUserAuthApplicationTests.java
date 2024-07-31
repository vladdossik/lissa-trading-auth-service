package lissa.trading.auth.service;

import lissa.trading.auth.service.service.UserServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtUserAuthApplicationTests {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private UserServiceImpl userService;

    @Test
    void contextLoads() {
        assertThat(applicationContext).isNotNull();
    }

    @Test
    void userServiceBeanExists() {
        assertThat(userService).isNotNull();
    }
}