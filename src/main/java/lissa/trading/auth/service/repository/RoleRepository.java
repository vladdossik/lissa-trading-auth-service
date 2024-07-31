package lissa.trading.auth.service.repository;

import lissa.trading.auth.service.model.Role;
import lissa.trading.auth.service.model.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRole(Roles role);
}