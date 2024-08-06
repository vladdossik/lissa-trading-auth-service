package lissa.trading.auth.service.service;

import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.model.User;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UserServiceImplTest extends BaseTest {

    @InjectMocks
    private UserServiceImpl userService;

    @BeforeEach
    public void setUp() {
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);
        ReflectionTestUtils.setField(userService, "roleRepository", roleRepository);
        ReflectionTestUtils.setField(userService, "encoder", encoder);
    }

    @Test
    public void testRegisterUser_UserAlreadyExistsByName() {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setFirstName("existingUser");
        signupRequest.setTelegramNickname("nickname");

        when(userRepository.existsByFirstName("existingUser")).thenReturn(true);

        UserRegistrationResponse response = userService.registerUser(signupRequest);

        assertEquals("Error: Username already taken!", response.getMessage());
    }

    @Test
    public void testRegisterUser_UserAlreadyExistsByNickname() {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setFirstName("newUser");
        signupRequest.setTelegramNickname("existingNickname");

        when(userRepository.existsByFirstName("newUser")).thenReturn(false);
        when(userRepository.existsByTelegramNickname("existingNickname")).thenReturn(true);

        UserRegistrationResponse response = userService.registerUser(signupRequest);

        assertEquals("Error: Nickname already in use!", response.getMessage());
    }

    @Test
    public void testRegisterUser_Success() {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setFirstName("newUser");
        signupRequest.setTelegramNickname("nickname");
        signupRequest.setPassword("password");

        Role userRole = createRole(Roles.ROLE_USER);

        when(userRepository.existsByFirstName("newUser")).thenReturn(false);
        when(userRepository.existsByTelegramNickname("nickname")).thenReturn(false);
        when(encoder.encode("password")).thenReturn("encodedPassword");
        when(roleRepository.findByRole(Roles.ROLE_USER)).thenReturn(Optional.of(userRole));

        UserRegistrationResponse response = userService.registerUser(signupRequest);

        assertEquals("User registered successfully!", response.getMessage());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    public void testSetUserInfo() {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setFirstName("firstName");
        signupRequest.setLastName("lastName");
        signupRequest.setTelegramNickname("telegramNickname");
        signupRequest.setTinkoffToken("tinkoffToken");
        signupRequest.setPassword("password");
        signupRequest.setRole(Set.of("user", "admin"));

        Role userRole = createRole(Roles.ROLE_USER);
        Role adminRole = createRole(Roles.ROLE_ADMIN);

        when(encoder.encode("password")).thenReturn("encodedPassword");
        when(roleRepository.findByRole(Roles.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByRole(Roles.ROLE_ADMIN)).thenReturn(Optional.of(adminRole));

        User user = ReflectionTestUtils.invokeMethod(userService, "setUserInfo", signupRequest);

        assertEquals("firstName", user.getFirstName());
        assertEquals("lastName", user.getLastName());
        assertEquals("telegramNickname", user.getTelegramNickname());
        assertEquals("tinkoffToken", user.getTinkoffToken());
        assertEquals("encodedPassword", user.getPassword());
        assertTrue(user.getRoles().contains(userRole));
        assertTrue(user.getRoles().contains(adminRole));
    }

    @Test
    public void testResolveRoles() {
        Set<String> strRoles = new HashSet<>();
        strRoles.add("admin");

        Role userRole = createRole(Roles.ROLE_USER);
        Role adminRole = createRole(Roles.ROLE_ADMIN);

        when(roleRepository.findByRole(Roles.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByRole(Roles.ROLE_ADMIN)).thenReturn(Optional.of(adminRole));

        Set<Role> roles = ReflectionTestUtils.invokeMethod(userService, "resolveRoles", strRoles);

        assertTrue(roles.contains(userRole));
        assertTrue(roles.contains(adminRole));
    }

    @Test
    public void testGetRole() {
        Role userRole = createRole(Roles.ROLE_USER);

        when(roleRepository.findByRole(Roles.ROLE_USER)).thenReturn(Optional.of(userRole));

        Role result = ReflectionTestUtils.invokeMethod(userService, "getRole", Roles.ROLE_USER);

        assertEquals(userRole, result);
    }

    @Test
    public void testGetRole_RoleNotFound() {
        when(roleRepository.findByRole(Roles.ROLE_USER)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            ReflectionTestUtils.invokeMethod(userService, "getRole", Roles.ROLE_USER);
        });

        assertEquals("Error: Role not found.", exception.getMessage());
    }

    @Test
    public void testGetRoleEnum() {
        assertEquals(Roles.ROLE_ADMIN, ReflectionTestUtils.invokeMethod(userService, "getRoleEnum", "admin"));
        assertEquals(Roles.ROLE_VIP, ReflectionTestUtils.invokeMethod(userService, "getRoleEnum", "vip"));
        assertEquals(Roles.ROLE_USER, ReflectionTestUtils.invokeMethod(userService, "getRoleEnum", "user"));
    }
}