package lissa.trading.auth.service.dataInit;

import lissa.trading.auth.service.model.Roles;
import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.repository.RoleRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer {

    private final RoleRepository roleRepository;

    @Autowired
    public DataInitializer(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @PostConstruct
    public void init() {
        if (roleRepository.count() == 0) {
            Role adminRole = new Role();
            adminRole.setRole(Roles.ROLE_ADMIN);
            roleRepository.save(adminRole);

            Role vipRole = new Role();
            vipRole.setRole(Roles.ROLE_VIP);
            roleRepository.save(vipRole);

            Role userRole = new Role();
            userRole.setRole(Roles.ROLE_USER);
            roleRepository.save(userRole);
        }
    }
}