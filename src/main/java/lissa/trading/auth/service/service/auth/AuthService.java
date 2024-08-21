package lissa.trading.auth.service.service.auth;

import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.TokenRefreshRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;

public interface AuthService {
    JwtResponse authenticateUser(LoginRequest loginRequest);

    JwtResponse refreshToken(TokenRefreshRequest request);
}
