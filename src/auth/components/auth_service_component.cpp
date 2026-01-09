#include <auth/components/auth_service_component.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>
#include <auth/infra/db/pg/repositories/postgres_user_repository.hpp>
#include <auth/infra/db/pg/transactions/postgres_transaction_manager.hpp>
#include <auth/infra/messaging/smtp_email_sender.hpp>
#include <auth/infra/providers/email/log_email_verification_sender.hpp>
#include <auth/infra/providers/email/smtp_email_verification_sender.hpp>
#include <auth/infra/security/password/bcrypt_password_hasher.hpp>
#include <auth/infra/security/verification/random_verification_code_generator.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::components {
    namespace {
        infra::messaging::smtp::TlsMode ParseTlsMode(std::string_view s) {
            if (s == "none") return infra::messaging::smtp::TlsMode::kNone;
            if (s == "starttls") return infra::messaging::smtp::TlsMode::kStartTls;
            if (s == "tls") return infra::messaging::smtp::TlsMode::kTls;
            throw std::runtime_error("invalid smtp.tls_mode: " + std::string{s});
        }

        infra::messaging::smtp::SmtpConfig BuildSmtpConfig(const userver::components::ComponentConfig &cfg) {
            const auto &s = cfg["smtp"];

            infra::messaging::smtp::SmtpConfig out;
            out.host = s["host"].As<std::string>();
            out.port = static_cast<std::uint16_t>(s["port"].As<int>(587));
            out.tls_mode = ParseTlsMode(s["tls_mode"].As<std::string>("starttls"));
            out.username = s["username"].As<std::string>();
            out.app_password = s["app_password"].As<std::string>();
            out.connect_timeout_ms = std::chrono::milliseconds{s["connect_timeout_ms"].As<int>(20000)};
            out.timeout_ms = std::chrono::milliseconds{s["timeout_ms"].As<int>(30000)};
            return out;
        }
    }

    struct AuthServiceComponent::Impl {
        infra::db::pg::PostgresEmailOutboxRepository email_outbox_repo;
        infra::db::pg::PostgresUserRepository user_repo;
        infra::db::pg::PgTransactionManager transaction_manager;

        infra::providers::email::SmtpEmailVerificationSender smtp_email_verification_sender;
        infra::providers::email::LogEmailVerificationSender log_email_verification_sender;

        infra::security::BcryptPasswordHasher password_hasher;
        infra::security::RandomVerificationCodeGenerator code_generator;
        services::usecases::AuthService auth_service;

        Impl(const userver::components::ComponentConfig &cfg,
             const userver::components::ComponentContext &ctx)
            : email_outbox_repo(ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster())
              , user_repo(ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster())
              , transaction_manager(ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster())
              , smtp_email_verification_sender(
                  infra::messaging::SmtpEmailSender(
                      BuildSmtpConfig(cfg),
                      cfg["smtp"]["from_email"].As<std::string>(),
                      cfg["smtp"]["from_name"].As<std::string>("")
                  )
              )
              , log_email_verification_sender(smtp_email_verification_sender)
              , password_hasher()
              , code_generator(6)
              , auth_service(
                  user_repo,
                  password_hasher,
                  log_email_verification_sender,
                  code_generator,
                  email_outbox_repo,
                  transaction_manager
              ) {
        }
    };

    AuthServiceComponent::AuthServiceComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx),
          impl_(std::make_unique<Impl>(cfg, ctx)) {
    }

    AuthServiceComponent::~AuthServiceComponent() = default;

    userver::yaml_config::Schema AuthServiceComponent::GetStaticConfigSchema() {
        using userver::yaml_config::MergeSchemas;
        using userver::components::LoggableComponentBase;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth service component config
additionalProperties: false
properties:
  smtp:
    type: object
    description: SMTP settings for verification emails
    additionalProperties: false
    properties:
      host:
        type: string
        description: SMTP server hostname
      port:
        type: integer
        description: SMTP server port
        default: 587
      tls_mode:
        type: string
        description: TLS mode
        enum: [none, starttls, tls]
        default: starttls
      username:
        type: string
        description: SMTP username
      app_password:
        type: string
        description: SMTP app password
      from_email:
        type: string
        description: RFC5322 From address
      from_name:
        type: string
        description: Optional display name for From header
        default: ""
      connect_timeout_ms:
        type: integer
        description: Connect timeout in milliseconds
        default: 20000
      timeout_ms:
        type: integer
        description: Total request timeout in milliseconds
        default: 30000
)");
    }


    services::usecases::AuthService &AuthServiceComponent::GetAuthService() noexcept {
        return impl_->auth_service;
    }

    const services::usecases::AuthService &AuthServiceComponent::GetAuthService() const noexcept {
        return impl_->auth_service;
    }
}
