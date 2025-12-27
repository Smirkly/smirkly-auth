#include <auth/services/auth_service.hpp>

namespace smirkly::auth::services::services {
    AuthService::AuthService(
        ports::UserRepository &user_repo,
        ports::PasswordHasher &password_hasher,
        ports::EmailVerificationSender &email_sender,
        ports::VerificationCodeGenerator &code_generator,
        ports::EmailOutboxRepository &email_outbox_repo
        /* dependences */
    )
        : user_repo_(user_repo),
          password_hasher_(password_hasher),
          email_sender_(email_sender),
          code_generator_(code_generator),
          email_outbox_repo_(email_outbox_repo) {
    }

    SignUpResult AuthService::SignUp(const SignUpCommand &cmd) {
        ports::NewUserData new_user_data = {
            .username = cmd.username,
            .password_hash = password_hasher_.Hash(cmd.password),
            .email = cmd.email,
            .phone = cmd.phone
        };

        domain::models::User user = user_repo_.Insert(new_user_data);

        if (user.email) {
            const std::string correlation_id = user.id;

            ports::EnqueueVerificationEmail job = {
                .to_email = *user.email,
                .code = code_generator_.Generate(),
                .correlation_id = correlation_id,
                .locale = "ru"
            };

            email_outbox_repo_.Insert(job);
        }

        return {std::move(user)};
    }
}
