#include <auth/services/auth_service.hpp>

namespace smirkly::auth::services::services {
    AuthService::AuthService(/* dependences */) {
    }

    SignUpResult AuthService::SignUp(const SignUpCommand &cmd) {
        domain::models::User user;
        user.id = "temp-fake-id";
        user.username = cmd.username;
        user.password = cmd.password;
        user.phone = cmd.phone;
        user.email = cmd.email;

        return {std::move(user)};
    }
}
