package lissa.trading.auth.service.service;

import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.TokenRefreshRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.service.auth.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthServiceImplTest extends BaseTest {

    @InjectMocks
    private AuthServiceImpl authService;

    @BeforeEach
    public void setUp() {
        ReflectionTestUtils.setField(authService, "authenticationManager", authenticationManager);
        ReflectionTestUtils.setField(authService, "jwtService", jwtService);
    }

    @Test
    void testAuthenticateUser_Success() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setTelegramNickname("user");
        loginRequest.setPassword("password");

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtService.generateJwtToken(authentication)).thenReturn("jwtToken");
        when(jwtService.generateRefreshToken(authentication)).thenReturn("refreshToken");

        JwtResponse jwtResponse = authService.authenticateUser(loginRequest);

        assertEquals("jwtToken", jwtResponse.getToken());
        assertEquals("refreshToken", jwtResponse.getRefreshToken());
    }

    @Test
    void testRefreshToken_Success() {
        TokenRefreshRequest request = new TokenRefreshRequest();
        request.setRefreshToken("validRefreshToken");

        UUID expectedExternalId = UUID.randomUUID();
        CustomUserDetails userDetails = new CustomUserDetails(
                1L, expectedExternalId, "firstname", "lastname",
                "user", "tinkoffToken", "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(jwtService.validateJwtToken("validRefreshToken")).thenReturn(true);
        when(jwtService.getUserNameFromJwtToken("validRefreshToken")).thenReturn("user");
        when(userDetailsService.loadUserByUsername("user")).thenReturn(userDetails);
        when(jwtService.generateJwtToken(any(Authentication.class))).thenReturn("newJwtToken");
        when(jwtService.generateRefreshToken(any(Authentication.class))).thenReturn("newRefreshToken");

        JwtResponse jwtResponse = authService.refreshToken(request);

        assertEquals("newJwtToken", jwtResponse.getToken());
        assertEquals("newRefreshToken", jwtResponse.getRefreshToken());
    }

    @Test
    void testRefreshToken_InvalidToken() {
        TokenRefreshRequest request = new TokenRefreshRequest();
        request.setRefreshToken("invalidRefreshToken");

        when(jwtService.validateJwtToken("invalidRefreshToken")).thenReturn(false);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.refreshToken(request);
        });

        assertEquals("Invalid refresh token", exception.getMessage());
    }
}