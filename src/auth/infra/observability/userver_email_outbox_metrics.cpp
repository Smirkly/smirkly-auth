#include <auth/infra/observability/userver_email_outbox_metrics.hpp>

#include <array>
#include <string_view>
#include <utility>
#include <vector>

#include <userver/utils/statistics/by_label_storage.hpp>
#include <userver/utils/statistics/histogram.hpp>
#include <userver/utils/statistics/metric_tag.hpp>
#include <userver/utils/statistics/metrics_storage.hpp>
#include <userver/utils/statistics/rate_counter.hpp>

namespace smirkly::auth::infra::observability {
namespace {

using services::ports::observability::EmailOutboxDeliveryOutcome;
using services::ports::observability::EmailOutboxErrorStage;

struct DeliveryLabels final {
  std::string_view result;
};

struct ErrorLabels final {
  std::string_view stage;
};

using DeliveryCounters = userver::utils::statistics::MonotonicByLabelStorage<
    DeliveryLabels, userver::utils::statistics::RateCounter>;
using ErrorCounters = userver::utils::statistics::MonotonicByLabelStorage<
    ErrorLabels, userver::utils::statistics::RateCounter>;

const userver::utils::statistics::MetricTag<DeliveryCounters> kDeliveryCounter{
    "auth.email-outbox.deliveries.total"};
const userver::utils::statistics::MetricTag<ErrorCounters> kErrorCounter{
    "auth.email-outbox.errors.total"};
const userver::utils::statistics::MetricTag<
    userver::utils::statistics::Histogram>
    kProcessingDuration{"auth.email-outbox.processing-duration-seconds",
                        std::vector<double>{0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
                                            1.0, 2.5, 5.0, 10.0, 30.0}};

constexpr std::array<std::string_view, 4> kDeliveryResults{
    "sent", "retry_scheduled", "dead", "lease_lost"};
constexpr std::array<std::string_view, 2> kErrorStages{"claim", "persist"};

std::string_view ToString(EmailOutboxDeliveryOutcome outcome) noexcept {
  switch (outcome) {
    case EmailOutboxDeliveryOutcome::kSent:
      return kDeliveryResults[0];
    case EmailOutboxDeliveryOutcome::kRetryScheduled:
      return kDeliveryResults[1];
    case EmailOutboxDeliveryOutcome::kDead:
      return kDeliveryResults[2];
    case EmailOutboxDeliveryOutcome::kLeaseLost:
      return kDeliveryResults[3];
  }
  return "unknown";
}

std::string_view ToString(EmailOutboxErrorStage stage) noexcept {
  switch (stage) {
    case EmailOutboxErrorStage::kClaim:
      return kErrorStages[0];
    case EmailOutboxErrorStage::kPersist:
      return kErrorStages[1];
  }
  return "unknown";
}

}  // namespace

UserverEmailOutboxMetrics::UserverEmailOutboxMetrics(
    userver::utils::statistics::MetricsStoragePtr metrics)
    : metrics_(std::move(metrics)) {
  auto& deliveries = metrics_->GetMetric(kDeliveryCounter);
  for (const auto result : kDeliveryResults) {
    (void)deliveries[DeliveryLabels{result}];
  }

  auto& errors = metrics_->GetMetric(kErrorCounter);
  for (const auto stage : kErrorStages) {
    (void)errors[ErrorLabels{stage}];
  }

  (void)metrics_->GetMetric(kProcessingDuration);
}

void UserverEmailOutboxMetrics::RecordDeliveryOutcome(
    EmailOutboxDeliveryOutcome outcome) noexcept {
  ++metrics_->GetMetric(kDeliveryCounter)[DeliveryLabels{ToString(outcome)}];
}

void UserverEmailOutboxMetrics::RecordError(
    EmailOutboxErrorStage stage) noexcept {
  ++metrics_->GetMetric(kErrorCounter)[ErrorLabels{ToString(stage)}];
}

void UserverEmailOutboxMetrics::ObserveProcessingDuration(
    std::chrono::duration<double> duration) noexcept {
  metrics_->GetMetric(kProcessingDuration).Account(duration.count());
}

}  // namespace smirkly::auth::infra::observability
