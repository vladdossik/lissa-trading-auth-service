package lissa.trading.auth.service.service;

import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.repository.RoleRepository;
import lissa.trading.auth.service.repository.UserRepository;
import lissa.trading.auth.service.security.jwt.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

public abstract class BaseTest {

    @Mock
    protected AuthenticationManager authenticationManager;

    @Mock
    protected UserRepository userRepository;

    @Mock
    protected RoleRepository roleRepository;

    @Mock
    protected PasswordEncoder encoder;

    @Mock
    protected JwtUtils jwtUtils;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    protected Role createRole(Roles role) {
        Role roleEntity = new Role();
        roleEntity.setRole(role);
        return roleEntity;
    }
}
