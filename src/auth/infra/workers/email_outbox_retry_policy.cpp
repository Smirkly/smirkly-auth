#include <auth/infra/workers/email_outbox_retry_policy.hpp>

#include <algorithm>

namespace smirkly::auth::infra::workers {

bool ShouldMarkEmailOutboxDead(std::size_t attempt, std::size_t max_attempts,
                               bool retryable) noexcept {
  return !retryable || attempt >= max_attempts;
}

std::chrono::seconds ComputeEmailOutboxRetryDelay(
    std::size_t attempt, const EmailOutboxRuntimeConfig& cfg) noexcept {
  const auto exponent = attempt == 0 ? 0 : attempt - 1;
  const auto pow2 = (exponent >= 30) ? (1ULL << 30) : (1ULL << exponent);
  const auto delay = std::chrono::seconds{cfg.retry_base_delay.count() *
                                          static_cast<long long>(pow2)};
  return std::min(delay, cfg.retry_max_delay);
}

}  // namespace smirkly::auth::infra::workers
