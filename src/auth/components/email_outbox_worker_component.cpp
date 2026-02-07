#include <auth/components/email_outbox_worker_component.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/logging/log.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/infra/messaging/smtp_email_sender.hpp>
#include <auth/infra/providers/email/log_email_verification_sender.hpp>
#include <auth/infra/providers/email/smtp_email_verification_sender.hpp>
#include <auth/infra/workers/email_outbox_processor.hpp>

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

        infra::workers::EmailOutboxProcessorConfig BuildWorkerConfig(const userver::components::ComponentConfig &cfg) {
            infra::workers::EmailOutboxProcessorConfig out;

            out.enabled = cfg["enabled"].As<bool>(true);
            out.poll_interval = std::chrono::milliseconds{cfg["poll_interval_ms"].As<int>(1000)};
            out.batch_size = static_cast<std::size_t>(cfg["batch_size"].As<int>(20));

            out.max_attempts = static_cast<std::size_t>(cfg["max_attempts"].As<int>(10));
            out.stuck_timeout = std::chrono::seconds{cfg["stuck_timeout_seconds"].As<int>(300)};

            out.retry_base_delay = std::chrono::seconds{cfg["retry_base_delay_seconds"].As<int>(2)};
            out.retry_max_delay = std::chrono::seconds{cfg["retry_max_delay_seconds"].As<int>(600)};
            return out;
        }
    }

    struct EmailOutboxWorkerComponent::Impl {
        AuthInfraComponent &infra;

        infra::workers::EmailOutboxProcessorConfig worker_cfg;

        std::unique_ptr<infra::providers::email::SmtpEmailVerificationSender> smtp_verification_sender;
        std::unique_ptr<infra::providers::email::LogEmailVerificationSender> verification_sender;
        std::unique_ptr<infra::workers::EmailOutboxProcessor> processor;

        Impl(const userver::components::ComponentConfig &cfg,
             const userver::components::ComponentContext &ctx)
            : infra(ctx.FindComponent<AuthInfraComponent>(AuthInfraComponent::kName))
              , worker_cfg(BuildWorkerConfig(cfg)) {
            if (!worker_cfg.enabled) {
                LOG_INFO() << "EmailOutboxWorkerComponent disabled by config";
                return;
            }

            const auto tp_name = cfg["task_processor"].As<std::string>("main-task-processor");
            auto &tp = ctx.GetTaskProcessor(tp_name);

            const auto from_email = cfg["smtp"]["from_email"].As<std::string>();
            const auto from_name = cfg["smtp"]["from_name"].As<std::string>("");

            smtp_verification_sender = std::make_unique<infra::providers::email::SmtpEmailVerificationSender>(
                std::make_unique<infra::messaging::SmtpEmailSender>(
                    BuildSmtpConfig(cfg),
                    from_email,
                    from_name)
            );

            verification_sender = std::make_unique<infra::providers::email::LogEmailVerificationSender>(
                *smtp_verification_sender
            );

            processor = std::make_unique<infra::workers::EmailOutboxProcessor>(
                infra.GetTransactionManager(),
                infra.GetEmailOutboxRepository(),
                *verification_sender,
                tp,
                worker_cfg
            );
        }
    };

    EmailOutboxWorkerComponent::EmailOutboxWorkerComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx)
          , impl_(std::make_unique<Impl>(cfg, ctx)) {
    }

    EmailOutboxWorkerComponent::~EmailOutboxWorkerComponent() {
        if (impl_ && impl_->processor) {
            impl_->processor->Stop();
        }
    }

    void EmailOutboxWorkerComponent::OnAllComponentsLoaded() {
        if (impl_ && impl_->processor) {
            impl_->processor->Start();
            LOG_INFO() << "EmailOutboxWorkerComponent started";
        }
    }

    void EmailOutboxWorkerComponent::OnAllComponentsAreStopping() {
        if (impl_ && impl_->processor) {
            impl_->processor->Stop();
            LOG_INFO() << "EmailOutboxWorkerComponent stopping";
        }
    }

    userver::yaml_config::Schema EmailOutboxWorkerComponent::GetStaticConfigSchema() {
        using userver::yaml_config::MergeSchemas;
        using userver::components::LoggableComponentBase;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Email outbox worker component
additionalProperties: false
properties:
  enabled:
    type: boolean
    description: Enable/disable outbox worker
    default: true

  task_processor:
    type: string
    description: Task processor name for worker periodic task
    default: main-task-processor

  poll_interval_ms:
    type: integer
    description: Poll interval in milliseconds
    default: 1000

  batch_size:
    type: integer
    description: Max jobs per tick
    default: 20

  max_attempts:
    type: integer
    description: Max attempts before marking job dead
    default: 10

  stuck_timeout_seconds:
    type: integer
    description: Requeue jobs stuck in processing longer than this
    default: 300

  retry_base_delay_seconds:
    type: integer
    description: Base delay for exponential backoff
    default: 2

  retry_max_delay_seconds:
    type: integer
    description: Max delay cap for exponential backoff
    default: 600

  smtp:
    type: object
    description: SMTP settings for verification emails (worker-only)
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
}
