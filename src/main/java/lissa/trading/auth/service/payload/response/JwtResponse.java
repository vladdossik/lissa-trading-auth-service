package lissa.trading.auth.service.payload.response;

import lissa.trading.auth.service.details.CustomUserDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;


import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String refreshToken;
    private UUID externalId;
    private String firstName;
    private String lastName;
    private String telegramNickname;
    private String tinkoffToken;
    private List<String> roles;

    public JwtResponse(String jwtToken, String refreshToken, CustomUserDetails userDetails) {
        this.token = jwtToken;
        this.refreshToken = refreshToken;
        this.externalId = userDetails.getExternalId();
        this.firstName = userDetails.getFirstName();
        this.lastName = userDetails.getLastName();
        this.telegramNickname = userDetails.getTelegramNickname();
        this.tinkoffToken = userDetails.getTinkoffToken();
        this.roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }
}
