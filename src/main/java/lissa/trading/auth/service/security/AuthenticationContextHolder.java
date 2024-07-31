package lissa.trading.auth.service.security;

import lissa.trading.auth.service.details.CustomUserDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class AuthenticationContextHolder {

    public static UserInfo getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            return new UserInfo(userDetails.getExternalId(), userDetails.getUsername());
        }
        return new UserInfo(UUID.randomUUID(), "anonymous");
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class UserInfo {
        private UUID externalId;
        private String userId;  // telegramNickname
    }
}