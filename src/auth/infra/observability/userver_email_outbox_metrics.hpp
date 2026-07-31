#pragma once

#include <userver/utils/statistics/metrics_storage_fwd.hpp>

#include <auth/services/ports/observability/email_outbox_metrics.hpp>

namespace smirkly::auth::infra::observability {

class UserverEmailOutboxMetrics final
    : public services::ports::observability::EmailOutboxMetrics {
 public:
  explicit UserverEmailOutboxMetrics(
      userver::utils::statistics::MetricsStoragePtr metrics);

  void RecordDeliveryOutcome(
      services::ports::observability::EmailOutboxDeliveryOutcome
          outcome) noexcept override;

  void RecordError(services::ports::observability::EmailOutboxErrorStage
                       stage) noexcept override;

  void ObserveProcessingDuration(
      std::chrono::duration<double> duration) noexcept override;

 private:
  userver::utils::statistics::MetricsStoragePtr metrics_;
};

}  // namespace smirkly::auth::infra::observability
