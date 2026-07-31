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
}  // namespace smirkly::auth::services::ports

namespace smirkly::auth::services::ports::observability {
class EmailOutboxMetrics;
}  // namespace smirkly::auth::services::ports::observability

namespace smirkly::auth::infra::workers {
struct EmailOutboxWorkerStaticConfig final {
  bool enabled{true};
  std::chrono::milliseconds poll_interval{1000};
};

class EmailOutboxProcessor final {
 public:
  EmailOutboxProcessor(
      services::ports::TransactionManager& tx_manager,
      services::ports::EmailOutboxRepository& outbox_repo,
      services::ports::EmailVerificationSender& sender,
      userver::engine::TaskProcessor& task_processor,
      EmailOutboxWorkerStaticConfig static_config,
      const EmailOutboxRuntimeConfigProvider& runtime_config_provider,
      services::ports::observability::EmailOutboxMetrics& metrics);

  ~EmailOutboxProcessor();

  EmailOutboxProcessor(const EmailOutboxProcessor&) = delete;

  EmailOutboxProcessor& operator=(const EmailOutboxProcessor&) = delete;

  void Start();

  void Stop() noexcept;

 private:
  void Tick();

 private:
  services::ports::TransactionManager& tx_manager_;
  services::ports::EmailOutboxRepository& outbox_repo_;
  services::ports::EmailVerificationSender& sender_;
  userver::engine::TaskProcessor& task_processor_;

  EmailOutboxWorkerStaticConfig static_config_;
  const EmailOutboxRuntimeConfigProvider& runtime_config_provider_;
  services::ports::observability::EmailOutboxMetrics& metrics_;
  userver::utils::PeriodicTask task_;
  bool started_{false};
};
}  // namespace smirkly::auth::infra::workers
