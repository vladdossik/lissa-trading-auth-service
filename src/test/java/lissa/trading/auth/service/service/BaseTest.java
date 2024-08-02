package lissa.trading.auth.service.service;

import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.repository.RoleRepository;
import lissa.trading.auth.service.repository.UserRepository;
import lissa.trading.auth.service.security.jwt.JwtUtils;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
public abstract class BaseTest {

    @Mock
    protected UserRepository userRepository;

    @Mock
    protected RoleRepository roleRepository;

    @Mock
    protected JwtUtils jwtUtils;

    @Mock
    protected PasswordEncoder encoder;

    @Mock
    protected AuthenticationManager authenticationManager;

    @Mock
    protected CustomUserDetailsService userDetailsService;

    protected Role createRole(Roles role) {
        Role roleEntity = new Role();
        roleEntity.setRole(role);
        return roleEntity;
    }
}
