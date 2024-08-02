package lissa.trading.auth.service.service;

import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.model.User;
import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;

import java.util.Set;

public interface UserService {
    JwtResponse authenticateUser(LoginRequest loginRequest);

    UserRegistrationResponse registerUser(SignupRequest signupRequest);

    User setUserInfo(SignupRequest signupRequest);

    Set<Role> resolveRoles(Set<String> strRoles);

    Role getRole(Roles role);

    Roles getRoleEnum(String role);
}