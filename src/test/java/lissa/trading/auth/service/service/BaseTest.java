package lissa.trading.auth.service.service;

import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.repository.RoleRepository;
import lissa.trading.auth.service.repository.UserRepository;
import lissa.trading.auth.service.security.jwt.JwtService;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;


@ExtendWith(MockitoExtension.class)
public abstract class BaseTest {

    @Mock
    protected UserRepository userRepository;

    @Mock
    protected RoleRepository roleRepository;

    @Mock
    protected JwtService jwtService;

    @Mock
    protected PasswordEncoder encoder;

    @Mock
    protected AuthenticationManager authenticationManager;

    @Mock
    protected CustomUserDetailsService userDetailsService;

    protected Role createRole(Roles role) {
        Role roleEntity = new Role();
        roleEntity.setUserRole(role);
        return roleEntity;
    }

    protected void setField(Object target, Object value) {
        ReflectionTestUtils.setField(target, "secretKeyString", value);
    }

    protected void invokePrivateMethod(Object target) throws Exception {
        var method = target.getClass().getDeclaredMethod("init");
        method.setAccessible(true);
        method.invoke(target);
    }

    protected String createSecretKeyString(int length) {
        return Base64.getEncoder().encodeToString(new byte[length]);
    }
}