package lissa.trading.auth.service.security.jwt;

import jakarta.servlet.http.HttpServletRequest;
import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.lissa.auth.lib.security.BaseAuthTokenFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthTokenFilter extends BaseAuthTokenFilter<CustomUserDetails> {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected boolean validateJwtToken(String token) {
        return jwtService.validateJwtToken(token);
    }

    @Override
    protected List<String> parseRoles(CustomUserDetails userInfo) {
        if (userInfo != null) {
            log.info("User info: {}", userInfo);
            return userInfo.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        }
        return Collections.emptyList();
    }

    @Override
    protected CustomUserDetails retrieveUserInfo(String token) {
        String username = jwtService.getUserNameFromJwtToken(token);
        return userDetailsService.loadUserByUsername(username);
    }

    @Override
    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith("/v1/internal/") ||
                requestURI.equals("/v1/auth/signup") ||
                requestURI.equals("/v1/auth/signin") ||
                requestURI.equals("/v1/auth/refresh-token") ||
                requestURI.startsWith("/swagger-ui/") ||
                requestURI.startsWith("/v3/api-docs/");
    }
}