#pragma once

#include <userver/components/loggable_component_base.hpp>

#include <auth/infra/db/pg/postgres_email_outbox_repository.hpp>
#include <auth/infra/db/pg/postgres_user_repository.hpp>
#include <auth/infra/providers/email/log_email_verification_sender.hpp>
#include <auth/infra/security/bcrypt_password_hasher.hpp>
#include <auth/infra/security/random_verification_code_generator.hpp>
#include <auth/services/auth_service.hpp>

namespace smirkly::auth::components {
    class AuthServiceComponent final : public userver::components::LoggableComponentBase {
    public:
        static constexpr std::string_view kName = "auth-service";

        AuthServiceComponent(const userver::components::ComponentConfig &cfg,
                             const userver::components::ComponentContext &ctx);

        static userver::yaml_config::Schema GetStaticConfigSchema();

        services::services::AuthService &GetService() noexcept;

        const services::services::AuthService &GetService() const noexcept;

    private:
        infra::db::pg::PostgresEmailOutboxRepository email_outbox_repo_;
        infra::db::pg::PostgresUserRepository user_repo_;
        infra::providers::email::EmailVerificationSender email_sender_;
        infra::security::BcryptPasswordHasher password_hasher_;
        infra::security::RandomVerificationCodeGenerator code_generator_;
        services::services::AuthService auth_service_;
    };
}
