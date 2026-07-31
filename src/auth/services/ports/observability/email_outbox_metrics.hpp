#pragma once

#include <chrono>

namespace smirkly::auth::services::ports::observability {

enum class EmailOutboxDeliveryOutcome {
  kSent,
  kRetryScheduled,
  kDead,
  kLeaseLost,
};

enum class EmailOutboxErrorStage {
  kClaim,
  kPersist,
};

class EmailOutboxMetrics {
 public:
  virtual ~EmailOutboxMetrics() = default;

  virtual void RecordDeliveryOutcome(
      EmailOutboxDeliveryOutcome outcome) noexcept = 0;

  virtual void RecordError(EmailOutboxErrorStage stage) noexcept = 0;

  virtual void ObserveProcessingDuration(
      std::chrono::duration<double> duration) noexcept = 0;
};

}  // namespace smirkly::auth::services::ports::observability
