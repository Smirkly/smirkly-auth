#pragma once

#include <auth/services/types/sign_up.hpp>
#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::services {
    class AuthService {
    public:
        AuthService(/* dependences */);

        SignUpResult SignUp(const SignUpCommand &cmd);
    };
}
