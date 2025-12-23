#include <auth/services/auth_service.hpp>

namespace smirkly::auth::services::services {
    AuthService::AuthService(
        ports::UserRepository &user_repo,
        ports::PasswordHasher &password_hasher,
        ports::EmailVerificationSender &email_sender,
        ports::VerificationCodeGenerator &code_generator
        /* dependences */
    )
        : user_repo_(user_repo),
          password_hasher_(password_hasher),
          email_sender_(email_sender),
          code_generator_(code_generator) {
    }

    SignUpResult AuthService::SignUp(const SignUpCommand &cmd) {
        domain::models::User user;
        user.id = "temp-fake-id";
        user.username = cmd.username;
        user.password = cmd.password;
        user.phone = cmd.phone;
        user.email = cmd.email;

        bool exists = user_repo_.ExistsByUsername(cmd.username);
        if (exists) {
            user.username = "EXISTS";
        }

        return {std::move(user)};
    }
}
