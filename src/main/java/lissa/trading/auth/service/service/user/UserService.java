package lissa.trading.auth.service.service.user;

import lissa.trading.auth.service.payload.request.SignupRequest;
import lissa.trading.auth.service.payload.response.UserRegistrationResponse;
import lissa.trading.auth_security_lib.dto.UserInfoDto;

public interface UserService {
    UserRegistrationResponse registerUser(SignupRequest signupRequest);

    UserInfoDto getUserInfoFromContext();
}