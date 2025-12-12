#include <auth/services/auth_service.hpp>

namespace smirkly::auth::domain::services {
    AuthService::AuthService(/* dependences */) {
    }

    AuthResult AuthService::SignUp(const SignUpCommand &cmd) {
        domain::models::User user;
        user.id = "temp-fake-id";
        user.username = cmd.username;
        user.password = cmd.password;
        user.phone = cmd.phone;
        user.email = cmd.email;

        domain::AuthTokens tokens{
            .access_token = "temp-fake-access-token",
            .refresh_token = "temp-fake-refresh-token"
        };

        return {user, tokens};
    }
}
