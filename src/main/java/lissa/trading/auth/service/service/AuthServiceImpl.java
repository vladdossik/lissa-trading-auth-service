package lissa.trading.auth.service.service;

import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.auth.service.exception.InvalidRefreshTokenException;
import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.TokenRefreshRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final EncryptionService encryptionService;

    @Transactional
    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getTelegramNickname(), loginRequest.getPassword()));

        String jwt = jwtService.generateJwtToken(authentication);
        String refreshToken = jwtService.generateRefreshToken(authentication);
        String encryptedToken = encryptionService.encrypt(((CustomUserDetails) authentication.getPrincipal()).getTinkoffToken());
        return new JwtResponse(jwt, refreshToken, encryptedToken);
    }

    @Transactional
    public JwtResponse refreshToken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        if (jwtService.validateJwtToken(requestRefreshToken)) {
            String username = jwtService.getUserNameFromJwtToken(requestRefreshToken);
            CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            String newJwt = jwtService.generateJwtToken(authentication);
            String newRefreshToken = jwtService.generateRefreshToken(authentication);

            return new JwtResponse(newJwt, newRefreshToken, encryptionService.encrypt(userDetails.getTinkoffToken()));

        } else {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }
    }
}