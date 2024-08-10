package lissa.trading.auth.service.service;

import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.model.User;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth.service.repository.RoleRepository;
import lissa.trading.auth.service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;

    @Override
    @Transactional
    public UserRegistrationResponse registerUser(SignupRequest signupRequest) {
        if (Boolean.TRUE.equals(userRepository.existsByFirstName(signupRequest.getFirstName()))) {
            return new UserRegistrationResponse("Error: Username already taken!");
        }

        if (Boolean.TRUE.equals(userRepository.existsByTelegramNickname(signupRequest.getTelegramNickname()))) {
            return new UserRegistrationResponse("Error: Nickname already in use!");
        }

        userRepository.save(setUserInfo(signupRequest));

        return new UserRegistrationResponse("User registered successfully!");
    }

    private User setUserInfo(SignupRequest signupRequest) {
        User user = new User();
        user.setFirstName(signupRequest.getFirstName());
        user.setLastName(signupRequest.getLastName());
        user.setTelegramNickname(signupRequest.getTelegramNickname());
        user.setTinkoffToken(signupRequest.getTinkoffToken());
        user.setRoles(resolveRoles(signupRequest.getRole()));
        user.setPassword(encoder.encode(signupRequest.getPassword()));
        return user;
    }

    private Set<Role> resolveRoles(Set<String> strRoles) {
        Set<Role> roles = new HashSet<>();
        if (strRoles != null) {
            strRoles.forEach(role -> roles.add(getRole(getRoleEnum(role))));
        }
        roles.add(getRole(Roles.ROLE_USER));
        return roles;
    }

    private Role getRole(Roles role) {
        return roleRepository.findByUserRole(role)
                .orElseThrow(() -> new RuntimeException("Error: Role not found."));
    }

    private Roles getRoleEnum(String role) {
        return switch (role.toLowerCase()) {
            case "admin" -> Roles.ROLE_ADMIN;
            case "vip" -> Roles.ROLE_VIP;
            default -> Roles.ROLE_USER;
        };
    }
}
