package lissa.trading.auth.service.security.internal;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Getter
@Slf4j
@Component
public class InternalTokenService {

    @Value("${security.internal.token}")
    private String internalToken;

    @PostConstruct
    private void init() {
        log.info("Internal token service initialized with token: {}", internalToken);
    }

    public boolean validateInternalToken(String token) {
        return internalToken.equals(token) && !token.isEmpty();
    }

    public String getServiceNameFromToken(String token) {
        return token;
    }

    public List<String> getRolesFromToken(String token) {
        if (validateInternalToken(token)) {
            return List.of("ROLE_INTERNAL_SERVICE");
        }
        return Collections.emptyList();
    }
}