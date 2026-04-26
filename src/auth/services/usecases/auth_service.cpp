#include <auth/services/usecases/auth_service.hpp>

#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/factories/device_factory.hpp>
#include <auth/services/factories/email_outbox_factory.hpp>
#include <auth/services/factories/email_verification_factory.hpp>
#include <auth/services/factories/session_factory.hpp>
#include <auth/services/factories/user_factory.hpp>
#include <auth/services/validation/sign_up_validator.hpp>

namespace smirkly::auth::services::usecases {
    AuthService::AuthService(
        ports::TransactionManager &transaction_manager,
        ports::UserRepository &user_repo,
        ports::EmailOutboxRepository &email_outbox_repo,
        ports::EmailVerificationRepository &email_verification_repo,
        ports::PasswordHasher &password_hasher,
        ports::VerificationCodeGenerator &code_generator,
        ports::security::JwtTokenProvider &token_provider,
        ports::DeviceRepository &device_repo,
        ports::SessionRepository &session_repo
        /* dependences */
    )
        : user_repo_(user_repo),
          password_hasher_(password_hasher),
          code_generator_(code_generator),
          email_outbox_repo_(email_outbox_repo),
          email_verification_repo_(email_verification_repo),
          transaction_manager_(transaction_manager),
          token_provider_(token_provider),
          device_repo(device_repo),
          session_repo(session_repo) {
    }


    contracts::SignUpResult AuthService::SignUp(
        const contracts::SignUpCommand &cmd,
        const contracts::RequestMeta &meta) {
        // TODO: move syntactic sign-up validation to SignUpValidator
        if (cmd.username.empty()) {
            throw services::errors::SignUpValidation("username is empty");
        }
        if (cmd.password.empty()) {
            throw services::errors::SignUpValidation("password is empty");
        }
        if (cmd.email && cmd.email->empty()) {
            throw services::errors::SignUpValidation("email is empty");
        }

        std::string normalized_username = cmd.username;
        // TODO: normalize and validate username before uniqueness check

        std::optional<std::string> email;
        if (cmd.email) {
            email = *cmd.email;
            // TODO: normalize email (trim + lower) and validate format before uniqueness check
        }

        // fast-fail
        if (user_repo_.ExistsByUsername(normalized_username)) {
            throw errors::UsernameTaken("username taken");
        }
        if (email && user_repo_.ExistsByEmail(*email)) {
            throw errors::EmailTaken("email taken");
        }

        const std::string password_hash = password_hasher_.Hash(cmd.password);

        auto new_user_data = factories::UserFactory::CreateFromSignUp(
            std::move(normalized_username),
            password_hash,
            std::move(email),
            cmd.phone
        );

        auto tx = transaction_manager_.Begin("auth.sign_up");

        domain::models::User user = user_repo_.Insert(*tx, new_user_data);

        if (user.email) {
            const std::string correlation_id = user.id;
            const std::string raw_code = code_generator_.Generate();
            const std::string code_hash = password_hasher_.Hash(raw_code);
            const auto now = std::chrono::system_clock::now();

            auto verification_data = factories::EmailVerificationFactory::Create(
                user.id,
                code_hash,
                meta,
                now,
                std::chrono::minutes{15}
            );

            email_verification_repo_.Insert(*tx, verification_data);

            auto job = factories::EmailOutboxFactory::VerificationEmail(
                *user.email,
                raw_code,
                user.id,
                "ru"
            );

            email_outbox_repo_.Insert(*tx, job);
        }

        tx->Commit();

        return {std::move(user)};
    }

    void AuthService::VerifyEmail(
        const contracts::VerifyEmailCommand &cmd,
        const contracts::RequestMeta &meta) {
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

    contracts::SignInResult AuthService::SignIn(
        const contracts::SignInCommand &cmd,
        const contracts::RequestMeta &meta) {
        if (!cmd.username && !cmd.email && !cmd.phone) {
            throw errors::SignInValidation("username/email/phone is required");
        }

        if (cmd.password.empty()) {
            throw errors::SignInValidation("password is required");
        }

        std::optional<domain::models::User> user_opt;
        if (cmd.username) {
            user_opt = user_repo_.FindByUsername(*cmd.username);
        } else if (cmd.email) {
            user_opt = user_repo_.FindByEmail(*cmd.email);
        } else if (cmd.phone) {
            user_opt = user_repo_.FindByPhone(*cmd.phone);
        }

        if (!user_opt) {
            throw errors::InvalidCredentials("invalid credentials");
        }

        const auto &user = *user_opt;

        const bool password_ok = password_hasher_.Verify(cmd.password, user.password);
        if (!password_ok) {
            throw errors::InvalidCredentials("invalid credentials");
        }

        // TODO: generate stable token family id for refresh-token rotation chain
        const std::string token_family_id = "generated-token-family-id";

        auto tokens = token_provider_.GenerateTokens(user.id);
        auto refresh_token_hash = password_hasher_.Hash(tokens.refresh_token);

        auto tx = transaction_manager_.Begin("auth.sign_in");

        auto new_device_data = factories::DeviceFactory::WebDevice(user.id, meta);
        auto device = device_repo.Insert(*tx, new_device_data);

        auto new_session_data = factories::SessionFactory::CreateForSignIn(
            user.id,
            device.id,
            std::move(refresh_token_hash),
            token_family_id,
            meta
        );

        domain::models::Session session = session_repo.Insert(*tx, new_session_data);
        tx->Commit();

        contracts::SignInResult result = {
            .user = user,
            .tokens = std::move(tokens),
            .session_id = session.id
        };

        return result;
    }
}
