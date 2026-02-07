#include <auth/services/usecases/auth_service.hpp>

#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/validation/sign_up_validator.hpp>

namespace smirkly::auth::services::usecases {
    AuthService::AuthService(
        ports::TransactionManager &transaction_manager,
        ports::UserRepository &user_repo,
        ports::EmailOutboxRepository &email_outbox_repo,
        ports::PasswordHasher &password_hasher,
        ports::VerificationCodeGenerator &code_generator
        /* dependences */
    )
        : user_repo_(user_repo),
          password_hasher_(password_hasher),
          code_generator_(code_generator),
          email_outbox_repo_(email_outbox_repo),
          transaction_manager_(transaction_manager) {
    }


    SignUpResult AuthService::SignUp(const SignUpCommand &cmd) {
        // TODO: убрать в sign_up_validator.сpp
        if (cmd.username.empty()) {
            throw services::errors::SignUpValidation("username is empty");
            // TODO: улучшить sign_up_errors.hpp
        }
        if (cmd.password.empty()) {
            throw services::errors::SignUpValidation("password is empty");
        }
        if (cmd.email && cmd.email->empty()) {
            throw services::errors::SignUpValidation("email is empty");
        }

        std::string normalized_username = cmd.username;
        // TODO: const auto username = NormalizeUsername(cmd.username);  // trim + lower + validate

        std::optional<std::string> email;
        // TODO: if (cmd.email) email = NormalizeEmail(*cmd.email);
        if (cmd.email) {
            email = *cmd.email;
            // TODO: normalize+validate email (lower+trim+format)
        }

        // fast-fail
        if (user_repo_.ExistsByUsername(normalized_username)) {
            throw errors::UsernameTaken("username taken");
        }
        if (email && user_repo_.ExistsByEmail(*email)) {
            throw errors::EmailTaken("email taken");
        }
        // TODO: вынести в sign_up_validator.cpp и сделать 1-м запросом (добавить метод в репозиторий)

        const std::string password_hash = password_hasher_.Hash(cmd.password);

        ports::NewUserData new_user_data = {
            .username = normalized_username,
            .password_hash = password_hash,
            .email = email,
            .phone = cmd.phone
        };

        auto tx = transaction_manager_.Begin("auth.sign_up");

        domain::models::User user = user_repo_.Insert(*tx, new_user_data);

        if (user.email) {
            const std::string correlation_id = user.id;

            ports::EnqueueVerificationEmail job = {
                .to_email = *user.email,
                .code = code_generator_.Generate(),
                .correlation_id = correlation_id,
                .locale = "ru"
            };

            email_outbox_repo_.Insert(*tx, job);
        }

        tx->Commit();

        return {std::move(user)};
    }
}
