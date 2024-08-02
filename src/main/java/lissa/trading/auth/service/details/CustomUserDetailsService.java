package lissa.trading.auth.service.details;

import lissa.trading.auth.service.model.User;
import lissa.trading.auth.service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String telegramNickname) throws UsernameNotFoundException {
        User user = userRepository.findByTelegramNickname(telegramNickname)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with telegram nickname: " + telegramNickname));

        return new CustomUserDetails(user);
    }
}
