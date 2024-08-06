package lissa.trading.auth.service.repository;

import lissa.trading.auth.service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByTelegramNickname(String telegramNickname);

    Boolean existsByFirstName(String firstName);

    Boolean existsByTelegramNickname(String telegramNickname);
}