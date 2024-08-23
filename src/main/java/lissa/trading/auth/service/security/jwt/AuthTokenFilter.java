package lissa.trading.auth.service.security.jwt;

import jakarta.servlet.http.HttpServletRequest;
import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.auth_security_lib.security.BaseAuthTokenFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthTokenFilter extends BaseAuthTokenFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected boolean validateJwtToken(String token) {
        return jwtService.validateJwtToken(token);
    }

    @Override
    protected List<String> parseRoles(Object userInfo) {
        if (userInfo instanceof CustomUserDetails userDetails) {
            log.info("User info: {}", userInfo);
            return userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        }
        return Collections.emptyList();
    }

    @Override
    protected Object retrieveUserInfo(String token) {
        String username = jwtService.getUserNameFromJwtToken(token);
        return userDetailsService.loadUserByUsername(username);
    }

    @Override
    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.equals("/api/auth/signup") ||
                requestURI.equals("/api/auth/signin") ||
                requestURI.equals("/api/auth/refresh-token") ||
                requestURI.startsWith("/swagger-ui/") ||
                requestURI.startsWith("/v3/api-docs/");
    }
}