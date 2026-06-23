#pragma once

#include <chrono>
#include <cstddef>

#include <userver/utils/periodic_task.hpp>

#include <auth/infra/workers/email_outbox_runtime_config.hpp>
#include <auth/infra/workers/email_outbox_runtime_config_provider.hpp>

namespace userver::engine {
    class TaskProcessor;
}

namespace smirkly::auth::services::ports {
    class TransactionManager;
    class EmailOutboxRepository;
    class EmailVerificationSender;
}

namespace smirkly::auth::infra::workers {
    struct EmailOutboxWorkerStaticConfig final {
        bool enabled{true};
        std::chrono::milliseconds poll_interval{1000};
    };

    class EmailOutboxProcessor final {
    public:
        EmailOutboxProcessor(services::ports::TransactionManager &tx_manager,
                             services::ports::EmailOutboxRepository &outbox_repo,
                             services::ports::EmailVerificationSender &sender,
                             userver::engine::TaskProcessor &task_processor,
                             EmailOutboxWorkerStaticConfig static_config,
                             const EmailOutboxRuntimeConfigProvider &runtime_config_provider);

        ~EmailOutboxProcessor();

        EmailOutboxProcessor(const EmailOutboxProcessor &) = delete;

        EmailOutboxProcessor &operator=(const EmailOutboxProcessor &) = delete;

        void Start();

        void Stop() noexcept;

    private:
        void Tick();

        std::chrono::seconds ComputeRetryDelay(
            std::size_t attempt,
            const EmailOutboxRuntimeConfig &cfg) const;

    private:
        services::ports::TransactionManager &tx_manager_;
        services::ports::EmailOutboxRepository &outbox_repo_;
        services::ports::EmailVerificationSender &sender_;
        userver::engine::TaskProcessor &task_processor_;

        EmailOutboxWorkerStaticConfig static_config_;
        const EmailOutboxRuntimeConfigProvider &runtime_config_provider_;
        userver::utils::PeriodicTask task_;
        bool started_{false};
    };
}
