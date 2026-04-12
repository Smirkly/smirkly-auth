#include <auth/services/usecases/auth_service.hpp>

#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/validation/sign_up_validator.hpp>

namespace smirkly::auth::services::usecases {
    AuthService::AuthService(
        ports::TransactionManager &transaction_manager,
        ports::UserRepository &user_repo,
        ports::EmailOutboxRepository &email_outbox_repo,
        ports::EmailVerificationRepository &email_verification_repo,
        ports::PasswordHasher &password_hasher,
        ports::VerificationCodeGenerator &code_generator
        /* dependences */
    )
        : user_repo_(user_repo),
          password_hasher_(password_hasher),
          code_generator_(code_generator),
          email_outbox_repo_(email_outbox_repo),
          email_verification_repo_(email_verification_repo),
          transaction_manager_(transaction_manager) {
    }


    contracts::SignUpResult AuthService::SignUp(const contracts::SignUpCommand &cmd) {
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
            const std::string raw_code = code_generator_.Generate();
            const std::string code_hash = password_hasher_.Hash(raw_code);
            const auto now = std::chrono::system_clock::now();

            ports::NewEmailVerificationData verification_data = {
                .user_id = user.id,
                .code_hash = code_hash,
                .expires_at = now + std::chrono::minutes(15),
                .ip = std::nullopt, // TODO: передать IP из контекста
                .user_agent = std::nullopt // TODO: передать user_agent из контекста
            };

            email_verification_repo_.Insert(*tx, verification_data);

            ports::EnqueueVerificationEmail job = {
                .to_email = *user.email,
                .code = raw_code,
                .correlation_id = correlation_id,
                .locale = "ru"
            };

            email_outbox_repo_.Insert(*tx, job);
        }

        tx->Commit();

        return {std::move(user)};
    }

    void AuthService::VerifyEmail(const contracts::VerifyEmailCommand &cmd) {
        const auto user_opt = user_repo_.FindByEmail(cmd.email);

        if (!user_opt) {
            throw errors::UserNotFound("User not found");
        }

        const auto &user = *user_opt;

        if (user.is_email_verified) {
            throw errors::AlreadyVerified("User already verified");
        }

        const auto now = std::chrono::system_clock::now();
        const auto verification_opt = email_verification_repo_.FindActiveByUserId(user.id, now);

        if (!verification_opt) {
            throw errors::CodeExpired("Verification code expired or not found");
        }

        const auto &verification = *verification_opt;
        const bool code_ok = password_hasher_.Verify(cmd.code, verification.code_hash);

        if (!code_ok) {
            auto tx = transaction_manager_.Begin("auth.verify_email.invalid_code");
            email_verification_repo_.IncrementAttempts(*tx, verification.id, now);
            tx->Commit();

            throw errors::InvalidCode("Invalid verification code");
        }

        auto tx = transaction_manager_.Begin("auth.verify_email");

        email_verification_repo_.MarkUsed(*tx, verification.id, now);
        user_repo_.SetEmailVerified(*tx, user.id, true);

        tx->Commit();
    }
}
