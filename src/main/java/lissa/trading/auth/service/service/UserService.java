package lissa.trading.auth.service.service;

import lissa.trading.auth.service.dto.UserInfoDto;
import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;

public interface UserService {
    UserRegistrationResponse registerUser(SignupRequest signupRequest);

    UserInfoDto getUserInfoFromContext();
}