package lissa.trading.auth.service.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private UUID externalId;
    private String firstName;
    private String lastName;
    private String telegramNickname;
    private String tinkoffToken;
    private List<String> roles;
}
