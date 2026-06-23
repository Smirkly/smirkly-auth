#include <auth/components/email_outbox_worker_component.hpp>

#include <memory>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/logging/log.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/config/email_outbox_worker_config.hpp>
#include <auth/config/runtime_config_providers.hpp>
#include <auth/infra/messaging/smtp/smtp_email_sender.hpp>
#include <auth/infra/providers/email/log_email_verification_sender.hpp>
#include <auth/infra/providers/email/smtp_email_verification_sender.hpp>
#include <auth/infra/workers/email_outbox_processor.hpp>

namespace smirkly::auth::components {
    struct EmailOutboxWorkerComponent::Impl {
        AuthInfraComponent &infra;
        config::EmailOutboxWorkerConfig worker_config;
        config::DynamicConfigEmailOutboxRuntimeConfigProvider runtime_config_provider;

        std::unique_ptr<infra::providers::email::SmtpEmailVerificationSender> smtp_verification_sender;
        std::unique_ptr<infra::providers::email::LogEmailVerificationSender> verification_sender;
        std::unique_ptr<infra::workers::EmailOutboxProcessor> processor;

        Impl(const userver::components::ComponentConfig &cfg,
             const userver::components::ComponentContext &ctx)
            : infra(ctx.FindComponent<AuthInfraComponent>(AuthInfraComponent::kName))
              , worker_config(config::ParseEmailOutboxWorkerConfig(cfg))
              , runtime_config_provider(
                    ctx.FindComponent<userver::components::DynamicConfig>().GetSource()) {
            if (!worker_config.enabled) {
                LOG_INFO() << "EmailOutboxWorkerComponent disabled by config";
                return;
            }

            auto &tp = ctx.GetTaskProcessor(worker_config.task_processor_name);

            smtp_verification_sender = std::make_unique<infra::providers::email::SmtpEmailVerificationSender>(
                std::make_unique<infra::messaging::SmtpEmailSender>(
                    worker_config.smtp,
                    worker_config.from_email,
                    worker_config.from_name)
            );

            verification_sender = std::make_unique<infra::providers::email::LogEmailVerificationSender>(
                *smtp_verification_sender
            );

            processor = std::make_unique<infra::workers::EmailOutboxProcessor>(
                infra.GetTransactionManager(),
                infra.GetEmailOutboxRepository(),
                *verification_sender,
                tp,
                worker_config.worker,
                runtime_config_provider
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
    default: email-outbox-task-processor

  poll_interval_ms:
    type: integer
    description: Poll interval in milliseconds
    default: 1000

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
