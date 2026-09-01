#pragma once

#include <chrono>
#include <cstddef>

#include <auth/infra/workers/email_outbox_runtime_config.hpp>

namespace smirkly::auth::infra::workers {

[[nodiscard]] bool ShouldMarkEmailOutboxDead(std::size_t attempt,
                                             std::size_t max_attempts,
                                             bool retryable) noexcept;

[[nodiscard]] std::chrono::seconds ComputeEmailOutboxRetryDelay(
    std::size_t attempt, const EmailOutboxRuntimeConfig& cfg) noexcept;

}  // namespace smirkly::auth::infra::workers
