package lissa.trading.auth.service.dto;

import lombok.Builder;

import java.util.List;

@Builder
public class UserInfoDto {
    private String firstName;
    private String lastName;
    private String telegramNickname;
    private String tinkoffToken;
    private List<String> role;
}