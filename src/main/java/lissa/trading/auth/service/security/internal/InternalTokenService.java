package lissa.trading.auth.service.security.internal;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Getter
@Slf4j
@Component
public class InternalTokenService {

    @Value("${integration.rest.user-service.token}")
    private String userServiceInternalToken;

    @Value("${integration.rest.tinkoff-api-service.token}")
    private String tinkoffApiServiceToken;

    protected boolean validateInternalToken(String token) {
        if (token.isEmpty()) {
            return false;
        }

        return new String(Base64.getDecoder().decode(userServiceInternalToken)).trim().equals(token)
                || new String(Base64.getDecoder().decode(tinkoffApiServiceToken)).trim().equals(token);
    }

    protected String getServiceNameFromToken(String token) {
        return token;
    }

    protected List<String> getRolesFromToken(String token) {
        return validateInternalToken(token)
                ? Collections.singletonList("ROLE_INTERNAL_SERVICE")
                : Collections.emptyList();
    }
}