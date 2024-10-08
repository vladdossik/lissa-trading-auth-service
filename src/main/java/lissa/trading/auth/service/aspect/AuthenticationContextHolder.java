package lissa.trading.auth.service.aspect;

import lissa.trading.auth.service.details.CustomUserDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;

public final class AuthenticationContextHolder {

    private AuthenticationContextHolder() {
        throw new IllegalStateException("Instantiation of utility class 'AuthenticationContextHolder' is not allowed.");
    }

    public static UserInfo getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            return new UserInfo(userDetails.getExternalId(), userDetails.getTelegramNickname());
        }
        return new UserInfo(UUID.randomUUID(), "anonymous");
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class UserInfo {
        private UUID externalId;
        private String telegramNickname;
    }
}