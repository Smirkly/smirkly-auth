#pragma once

#include <chrono>
#include <cstddef>

#include <userver/utils/periodic_task.hpp>

namespace userver::engine {
    class TaskProcessor;
}

namespace smirkly::auth::services::ports {
    class TransactionManager;
    class EmailOutboxRepository;
    class EmailVerificationSender;
}

namespace smirkly::auth::infra::workers {
    struct EmailOutboxProcessorConfig {
        bool enabled{true};
        std::chrono::milliseconds poll_interval{1000};
        std::size_t batch_size{20};

        std::size_t max_attempts{10};
        std::chrono::seconds stuck_timeout{300};

        std::chrono::seconds retry_base_delay{2};
        std::chrono::seconds retry_max_delay{600};
    };

    class EmailOutboxProcessor final {
    public:
        EmailOutboxProcessor(services::ports::TransactionManager &tx_manager,
                             services::ports::EmailOutboxRepository &outbox_repo,
                             services::ports::EmailVerificationSender &sender,
                             userver::engine::TaskProcessor &task_processor,
                             EmailOutboxProcessorConfig cfg);

        ~EmailOutboxProcessor();

        EmailOutboxProcessor(const EmailOutboxProcessor &) = delete;

        EmailOutboxProcessor &operator=(const EmailOutboxProcessor &) = delete;

        void Start();

        void Stop() noexcept;

    private:
        void Tick();

        std::chrono::seconds ComputeRetryDelay(std::size_t attempt) const;

    private:
        services::ports::TransactionManager &tx_manager_;
        services::ports::EmailOutboxRepository &outbox_repo_;
        services::ports::EmailVerificationSender &sender_;
        userver::engine::TaskProcessor &task_processor_;

        EmailOutboxProcessorConfig cfg_;
        userver::utils::PeriodicTask task_;
        bool started_{false};
    };
}
