#include <auth/services/usecases/auth_service.hpp>

#include <chrono>
#include <stdexcept>

#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/change_password_errors.hpp>
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
    namespace {
        bool LimitExceeded(std::size_t count, std::size_t limit) {
            return limit > 0 && count >= limit;
        }

        bool ShouldUpdateLastUsed(
            const domain::models::Session &session,
            std::chrono::system_clock::time_point now,
            std::chrono::seconds threshold
        ) {
            return !session.last_used_at ||
                   *session.last_used_at + threshold <= now;
        }
    }

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
        ports::support::IdGenerator &id_generator,
        policies::SessionPolicy session_policy,
        policies::SignInPolicy sign_in_policy,
        policies::EmailVerificationPolicy email_verification_policy
        /* dependences */
    )
        : user_repo_(user_repo),
          email_outbox_repo_(email_outbox_repo),
          email_verification_repo_(email_verification_repo),
          device_repo(device_repo),
          session_repo(session_repo),
          transaction_manager_(transaction_manager),
          token_provider_(token_provider),
          password_hasher_(password_hasher),
          code_generator_(code_generator),
          id_generator_(id_generator),
          email_verification_policy_(email_verification_policy),
          session_policy_(session_policy),
          sign_in_policy_(sign_in_policy) {
        if (session_policy_.refresh_token_ttl <= std::chrono::seconds{0}) {
            throw std::runtime_error("session refresh token TTL must be positive");
        }
        if (session_policy_.activity_update_threshold < std::chrono::seconds{0}) {
            throw std::runtime_error("session activity update threshold must not be negative");
        }
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
        const contracts::RequestMeta &meta) {
        const auto now = std::chrono::system_clock::now();
        const auto user_opt = user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

        if (user_opt && user_opt->is_email_verified) {
            throw errors::AlreadyVerified("User already verified");
        }

        std::optional<std::string> user_id;
        if (user_opt) {
            user_id = user_opt->id;
        }

        const auto since = now - email_verification_policy_.rate_limit_window;
        const auto counters = email_verification_repo_.CountRecentAttempts(
            cmd.email,
            user_id,
            meta.ip,
            since
        );

        if (LimitExceeded(counters.email, email_verification_policy_.max_attempts_per_email) ||
            LimitExceeded(counters.user, email_verification_policy_.max_attempts_per_user) ||
            LimitExceeded(counters.ip, email_verification_policy_.max_attempts_per_ip)) {
            throw errors::TooManyVerificationAttempts("too many verification attempts");
        }

        {
            auto tx = transaction_manager_.Begin("auth.verify_email.record_attempt");
            email_verification_repo_.RecordAttempt(*tx, cmd.email, user_id, meta.ip, meta.user_agent, now);
            tx->Commit();
        }

        if (!user_opt) {
            throw errors::UserNotFound("User not found");
        }

        const auto &user = *user_opt;
        const auto verification_opt = email_verification_repo_.FindActiveByUserId(
            user.id,
            now,
            email_verification_policy_.max_code_attempts
        );

        if (!verification_opt) {
            throw errors::CodeExpired("Verification code expired or not found");
        }

        const auto &verification = *verification_opt;
        const bool code_ok = password_hasher_.Verify(cmd.code, verification.code_hash);

        if (!code_ok) {
            auto tx = transaction_manager_.Begin("auth.verify_email.invalid_code");
            email_verification_repo_.IncrementAttempts(
                *tx,
                verification.id,
                now,
                email_verification_policy_.max_code_attempts
            );
            tx->Commit();

            throw errors::InvalidCode("Invalid verification code");
        }

        auto tx = transaction_manager_.Begin("auth.verify_email");

        email_verification_repo_.MarkUsed(*tx, verification.id, now);
        user_repo_.SetEmailVerified(*tx, user.id, true);

        tx->Commit();
    }

    void AuthService::ResendEmailVerification(
        const contracts::ResendEmailVerificationCommand &cmd,
        const contracts::RequestMeta &meta) {
        const auto now = std::chrono::system_clock::now();
        const auto user_opt = user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

        std::optional<std::string> user_id;
        if (user_opt) {
            user_id = user_opt->id;
        }

        const auto since = now - email_verification_policy_.rate_limit_window;
        const auto counters = email_verification_repo_.CountRecentAttempts(
            cmd.email,
            user_id,
            meta.ip,
            since
        );

        if (LimitExceeded(counters.email, email_verification_policy_.max_attempts_per_email) ||
            LimitExceeded(counters.user, email_verification_policy_.max_attempts_per_user) ||
            LimitExceeded(counters.ip, email_verification_policy_.max_attempts_per_ip)) {
            throw errors::TooManyVerificationAttempts("too many verification attempts");
        }

        auto tx = transaction_manager_.Begin("auth.resend_email_verification");
        email_verification_repo_.RecordAttempt(*tx, cmd.email, user_id, meta.ip, meta.user_agent, now);

        if (user_opt && !user_opt->is_email_verified && user_opt->email) {
            email_verification_repo_.MarkActiveUsedByUserId(*tx, user_opt->id, now);

            const std::string raw_code = code_generator_.Generate();
            const std::string code_hash = password_hasher_.Hash(raw_code);

            auto verification_data = factories::EmailVerificationFactory::Create(
                user_opt->id,
                code_hash,
                meta,
                now,
                std::chrono::minutes{15}
            );

            email_verification_repo_.Insert(*tx, verification_data);

            auto job = factories::EmailOutboxFactory::VerificationEmail(
                *user_opt->email,
                raw_code,
                user_opt->id,
                "ru"
            );

            email_outbox_repo_.Insert(*tx, job);
        }

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
            user_opt = user_repo_.FindByUsername(*cmd.username, ports::ReadConsistency::kStrong);
        } else if (cmd.email) {
            user_opt = user_repo_.FindByEmail(*cmd.email, ports::ReadConsistency::kStrong);
        } else if (cmd.phone) {
            user_opt = user_repo_.FindByPhone(*cmd.phone, ports::ReadConsistency::kStrong);
        }

        if (!user_opt) {
            throw errors::InvalidCredentials("invalid credentials");
        }
        const auto &user = *user_opt;

        const bool password_ok = password_hasher_.Verify(cmd.password, user.password);
        if (!password_ok) {
            throw errors::InvalidCredentials("invalid credentials");
        }

        if (sign_in_policy_.require_verified_email &&
            user.email.has_value() &&
            !user.is_email_verified) {
            throw errors::EmailNotVerified("email is not verified");
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
            meta,
            session_policy_.refresh_token_ttl
        );

        domain::models::Session session = session_repo_.Insert(*tx, new_session_data);
        tx->Commit();

        contracts::SignInResult result = {
            .user = user,
            .tokens = std::move(tokens),
            .session_id = session.id,
            .refresh_token_max_age = session_policy_.refresh_token_ttl
        };

        return result;
    }


    contracts::RefreshResult AuthService::Refresh(
        const contracts::RefreshCommand &cmd,
        const contracts::RequestMeta &meta) {
        if (cmd.refresh_token.empty()) {
            throw errors::InvalidRefreshToken("refresh token is empty");
        }

        const auto claims = token_provider_.ParseRefreshToken(cmd.refresh_token);

        const auto session_opt = session_repo.FindById(claims.session_id, ports::ReadConsistency::kStrong);
        if (!session_opt) {
            throw errors::RefreshSessionNotFound("session not found");
        }

        const auto session = *session_opt;
        const auto now = std::chrono::system_clock::now();

        if (session.user_id != claims.user_id) {
            throw errors::InvalidRefreshToken("refresh token subject mismatch");
        }

        if (!claims.token_family_id || *claims.token_family_id != session.token_family_id) {
            throw errors::InvalidRefreshToken("refresh token family mismatch");
        }

        if (session.revoked_at.has_value()) {
            const bool reused_refresh_token = password_hasher_.Verify(
                cmd.refresh_token,
                session.refresh_token_hash
            );

            if (reused_refresh_token) {
                auto tx = transaction_manager_.Begin("auth.refresh.reuse_detected");
                session_repo_.RevokeByTokenFamily(*tx, session.user_id, session.token_family_id);
                tx->Commit();

                throw errors::RefreshTokenReuseDetected("refresh token reuse detected");
            }

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

        const std::string new_session_id = id_generator_.Generate();
        auto tokens = token_provider_.GenerateTokens(
            session.user_id,
            new_session_id,
            session.token_family_id
        );
        auto new_refresh_token_hash = password_hasher_.Hash(tokens.refresh_token);

        auto replacement_session_data = factories::SessionFactory::CreateForRefreshRotation(
            new_session_id,
            session,
            std::move(new_refresh_token_hash),
            meta,
            session_policy_.refresh_token_ttl
        );

        auto tx = transaction_manager_.Begin("auth.refresh");
        const auto replacement_session = session_repo_.Insert(*tx, replacement_session_data);
        const bool old_session_revoked = session_repo_.RevokeAndReplace(
            *tx,
            session.id,
            replacement_session.id
        );
        if (!old_session_revoked) {
            throw errors::RefreshSessionRevoked("session already rotated");
        }
        tx->Commit();

        contracts::RefreshResult result = {
            .access_token = std::move(tokens.access_token),
            .refresh_token = std::move(tokens.refresh_token),
            .session_id = replacement_session.id,
            .refresh_token_max_age = session_policy_.refresh_token_ttl
        };

        return result;
    }

    contracts::AuthContext AuthService::AuthenticateAccessToken(std::string_view access_token) {
        if (access_token.empty()) {
            throw errors::MissingAccessToken("access token is required");
        }

        const auto claims = token_provider_.ParseAccessToken(access_token);
        const auto session_opt = session_repo.FindById(claims.session_id, ports::ReadConsistency::kStrong);
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
        const auto now = std::chrono::system_clock::now();
        if (session.expires_at <= now) {
            throw errors::AuthSessionExpired("session expired");
        }

        const auto user_opt = user_repo_.FindById(claims.user_id, ports::ReadConsistency::kStrong);
        if (!user_opt) {
            throw errors::AuthUserNotFound("user not found");
        }

        if (ShouldUpdateLastUsed(
                session,
                now,
                session_policy_.activity_update_threshold)) {
            auto tx = transaction_manager_.Begin("auth.session_activity");
            session_repo.UpdateLastUsed(*tx, session.id, now);
            tx->Commit();
        }

        return {
            .user_id = claims.user_id,
            .session_id = claims.session_id,
        };
    }

    contracts::MeResult AuthService::GetMe(const contracts::AuthContext &context) {
        const auto user_opt = user_repo_.FindById(context.user_id, ports::ReadConsistency::kStrong);
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
            .sessions = session_repo.ListActiveByUserId(context.user_id, ports::ReadConsistency::kStrong),
        };
    }

    void AuthService::RevokeSession(
        const contracts::AuthContext &context,
        std::string_view session_id
    ) {
        const auto target_session = session_repo.FindById(session_id, ports::ReadConsistency::kStrong);
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

    void AuthService::RevokeCurrentSession(const contracts::AuthContext &context) {
        RevokeSession(context, context.session_id);
    }

    void AuthService::RevokeAllSessions(const contracts::AuthContext &context) {
        auto tx = transaction_manager_.Begin("auth.sessions.revoke_all");
        session_repo.RevokeAllByUserId(*tx, context.user_id);
        tx->Commit();
    }

    void AuthService::ChangePassword(
        const contracts::AuthContext &context,
        const contracts::ChangePasswordCommand &cmd
    ) {
        if (cmd.current_password.empty()) {
            throw errors::ChangePasswordValidation("current password is required");
        }

        try {
            sign_up_validator_.ValidatePassword(cmd.new_password);
        } catch (const errors::SignUpValidation &e) {
            throw errors::ChangePasswordValidation(e.what());
        }

        const auto user_opt = user_repo_.FindById(context.user_id, ports::ReadConsistency::kStrong);
        if (!user_opt) {
            throw errors::AuthUserNotFound("user not found");
        }

        const auto &user = *user_opt;
        if (!password_hasher_.Verify(cmd.current_password, user.password)) {
            throw errors::InvalidCurrentPassword("invalid current password");
        }

        if (password_hasher_.Verify(cmd.new_password, user.password)) {
            throw errors::ChangePasswordValidation("new password must differ from current password");
        }

        const auto new_password_hash = password_hasher_.Hash(cmd.new_password);

        auto tx = transaction_manager_.Begin("auth.change_password");
        user_repo_.UpdatePasswordHash(*tx, context.user_id, new_password_hash);
        session_repo.RevokeAllByUserId(*tx, context.user_id);
        tx->Commit();
    }
}
