package lissa.trading.auth.service.service;

import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.model.User;
import lissa.trading.auth.service.payload.request.LoginRequest;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.JwtResponse;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth.service.repository.RoleRepository;
import lissa.trading.auth.service.repository.UserRepository;
import lissa.trading.auth.service.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    @Override
    @Transactional
    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getTelegramNickname(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(jwt, userDetails.getExternalId(), userDetails.getFirstName(),
                userDetails.getLastName(), userDetails.getTelegramNickname(), userDetails.getTinkoffToken(), roles);
    }

    @Override
    @Transactional
    public UserRegistrationResponse registerUser(SignupRequest signupRequest) {
        if (userRepository.existsByFirstName(signupRequest.getFirstName())) {
            return new UserRegistrationResponse("Error: Username already taken!");
        }

        if (userRepository.existsByTelegramNickname(signupRequest.getTelegramNickname())) {
            return new UserRegistrationResponse("Error: Nickname already in use!");
        }

        userRepository.save(setUserInfo(signupRequest));

        return new UserRegistrationResponse("User registered successfully!");
    }

    @Override
    @Transactional
    public User setUserInfo(SignupRequest signupRequest) {
        User user = new User();
        user.setFirstName(signupRequest.getFirstName());
        user.setLastName(signupRequest.getLastName());
        user.setTelegramNickname(signupRequest.getTelegramNickname());
        user.setTinkoffToken(signupRequest.getTinkoffToken());
        user.setRoles(resolveRoles(signupRequest.getRole()));
        user.setPassword(encoder.encode(signupRequest.getPassword()));
        return user;
    }

    @Override
    @Transactional
    public Set<Role> resolveRoles(Set<String> strRoles) {
        Set<Role> roles = new HashSet<>();

        if (strRoles != null) {
            strRoles.forEach(role -> roles.add(getRole(getRoleEnum(role))));
        }

        roles.add(getRole(Roles.ROLE_USER));

        return roles;
    }

    @Override
    @Transactional
    public Role getRole(Roles role) {
        return roleRepository.findByRole(role)
                .orElseThrow(() -> new RuntimeException("Error: Role not found."));
    }

    @Override
    public Roles getRoleEnum(String role) {
        return switch (role.toLowerCase()) {
            case "admin" -> Roles.ROLE_ADMIN;
            case "vip" -> Roles.ROLE_VIP;
            default -> Roles.ROLE_USER;
        };
    }
}