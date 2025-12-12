#pragma once

#include <auth/services/auth_service_types.hpp>
#include <auth/domain/models/user.hpp>

namespace smirkly::auth::domain::services {
    class AuthService {
    public:
        AuthService(/* dependences */);

        AuthResult SignUp(const SignUpCommand &cmd);
    };
}
