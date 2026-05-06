#include <auth/services/usecases/auth_service.hpp>

#include <chrono>

#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/refresh_errors.hpp>
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
        ports::SessionRepository &session_repo,
        ports::support::IdGenerator &id_generator
    )
        : user_repo_(user_repo),
          email_outbox_repo_(email_outbox_repo),
          email_verification_repo_(email_verification_repo),
          device_repo_(device_repo),
          session_repo_(session_repo),
          transaction_manager_(transaction_manager),
          token_provider_(token_provider),
          password_hasher_(password_hasher),
          code_generator_(code_generator),
          id_generator_(id_generator) {
    }


    contracts::SignUpResult AuthService::SignUp(
        const contracts::SignUpCommand &cmd,
        const contracts::RequestMeta &meta) {
        const auto input = sign_up_validator_.ValidateAndNormalize(cmd);
        const auto &normalized_username = input.username.Value();

        // fast-fail
        if (user_repo_.ExistsByUsername(normalized_username)) {
            throw errors::UsernameTaken("username taken");
        }
        if (input.email && user_repo_.ExistsByEmail(input.email->Value())) {
            throw errors::EmailTaken("email taken");
        }
        if (input.phone && user_repo_.ExistsByPhone(input.phone->Value())) {
            throw errors::PhoneTaken("phone taken");
        }

        const std::string password_hash = password_hasher_.Hash(input.password);

        std::optional<std::string> email;
        if (input.email) {
            email = input.email->Value();
        }

        std::optional<std::string> phone;
        if (input.phone) {
            phone = input.phone->Value();
        }

        auto new_user_data = factories::UserFactory::CreateFromSignUp(
            normalized_username,
            password_hash,
            std::move(email),
            std::move(phone)
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
        const contracts::RequestMeta &) {
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

        const std::string session_id = id_generator_.Generate();
        const std::string token_family_id = id_generator_.Generate();

        auto tokens = token_provider_.GenerateTokens(user.id, session_id, token_family_id);
        auto refresh_token_hash = password_hasher_.Hash(tokens.refresh_token);

        auto tx = transaction_manager_.Begin("auth.sign_in");

        auto new_device_data = factories::DeviceFactory::WebDevice(user.id, meta);
        auto device = device_repo_.Insert(*tx, new_device_data);

        auto new_session_data = factories::SessionFactory::CreateForSignIn(
            session_id,
            user.id,
            device.id,
            std::move(refresh_token_hash),
            token_family_id,
            meta
        );

        domain::models::Session session = session_repo_.Insert(*tx, new_session_data);
        tx->Commit();

        contracts::SignInResult result = {
            .user = user,
            .tokens = std::move(tokens),
            .session_id = session.id
        };

        return result;
    }


    contracts::RefreshResult AuthService::Refresh(
        const contracts::RefreshCommand &cmd,
        const contracts::RequestMeta &) {
        if (cmd.refresh_token.empty()) {
            throw errors::InvalidRefreshToken("refresh token is empty");
        }

        const auto claims = token_provider_.ParseRefreshToken(cmd.refresh_token);

        const auto session_opt = session_repo_.FindById(claims.session_id);
        if (!session_opt) {
            throw errors::RefreshSessionNotFound("session not found");
        }

        const auto &session = *session_opt;
        const auto now = std::chrono::system_clock::now();

        if (session.user_id != claims.user_id) {
            throw errors::InvalidRefreshToken("refresh token subject mismatch");
        }

        if (session.revoked_at.has_value()) {
            throw errors::RefreshSessionRevoked("session revoked");
        }

        if (session.expires_at <= now) {
            throw errors::RefreshSessionExpired("session expired");
        }

        const bool refresh_token_ok = password_hasher_.Verify(
            cmd.refresh_token,
            session.refresh_token_hash
        );

        if (!refresh_token_ok) {
            throw errors::InvalidRefreshToken("refresh token hash mismatch");
        }

        auto tx = transaction_manager_.Begin("auth.refresh");
        session_repo_.UpdateLastUsed(*tx, session.id, now);
        tx->Commit();

        contracts::RefreshResult result = {
            .access_token = token_provider_.GenerateAccessToken(session.user_id, session.id),
            .session_id = session.id
        };

        return result;
    }

    contracts::AuthContext AuthService::AuthenticateAccessToken(std::string_view access_token) {
        if (access_token.empty()) {
            throw errors::MissingAccessToken("access token is required");
        }

        const auto claims = token_provider_.ParseAccessToken(access_token);
        const auto session_opt = session_repo_.FindById(claims.session_id);
        if (!session_opt) {
            throw errors::AuthSessionNotFound("session not found");
        }

        const auto &session = *session_opt;
        if (session.user_id != claims.user_id) {
            throw errors::InvalidAccessToken("access token subject mismatch");
        }
        if (session.revoked_at) {
            throw errors::AuthSessionRevoked("session revoked");
        }
        if (session.expires_at <= std::chrono::system_clock::now()) {
            throw errors::AuthSessionExpired("session expired");
        }

        const auto user_opt = user_repo_.FindById(claims.user_id);
        if (!user_opt) {
            throw errors::AuthUserNotFound("user not found");
        }

        return {
            .user_id = claims.user_id,
            .session_id = claims.session_id,
        };
    }

    contracts::MeResult AuthService::GetMe(const contracts::AuthContext &context) {
        const auto user_opt = user_repo_.FindById(context.user_id);
        if (!user_opt) {
            throw errors::AuthUserNotFound("user not found");
        }

        return {
            .user = *user_opt,
            .session_id = context.session_id,
        };
    }

    contracts::SessionsResult AuthService::ListSessions(const contracts::AuthContext &context) {
        return {
            .sessions = session_repo_.ListActiveByUserId(context.user_id),
        };
    }

    void AuthService::RevokeSession(
        const contracts::AuthContext &context,
        std::string_view session_id
    ) {
        const auto target_session = session_repo_.FindById(session_id);
        if (!target_session) {
            throw errors::SessionNotFound("session not found");
        }
        if (target_session->user_id != context.user_id) {
            throw errors::SessionForbidden("session belongs to another user");
        }
        if (target_session->revoked_at) {
            return;
        }

        auto tx = transaction_manager_.Begin("auth.sessions.revoke");
        session_repo_.RevokeByUserId(*tx, session_id, context.user_id);
        tx->Commit();
    }
}
