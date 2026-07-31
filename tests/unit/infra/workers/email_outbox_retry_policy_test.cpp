#include <auth/infra/workers/email_outbox_retry_policy.hpp>

#include <chrono>

#include <userver/utest/utest.hpp>

namespace {
namespace workers = smirkly::auth::infra::workers;
using namespace std::chrono_literals;

workers::EmailOutboxRuntimeConfig MakeConfig() {
  workers::EmailOutboxRuntimeConfig config;
  config.retry_base_delay = 2s;
  config.retry_max_delay = 10s;
  return config;
}

UTEST(EmailOutboxRetryPolicy, ExponentialBackoffStartsFromClaimedAttempt) {
  const auto config = MakeConfig();

  EXPECT_EQ(workers::ComputeEmailOutboxRetryDelay(1, config), 2s);
  EXPECT_EQ(workers::ComputeEmailOutboxRetryDelay(2, config), 4s);
  EXPECT_EQ(workers::ComputeEmailOutboxRetryDelay(3, config), 8s);
}

UTEST(EmailOutboxRetryPolicy, BackoffIsCapped) {
  const auto config = MakeConfig();

  EXPECT_EQ(workers::ComputeEmailOutboxRetryDelay(4, config), 10s);
  EXPECT_EQ(workers::ComputeEmailOutboxRetryDelay(30, config), 10s);
}

UTEST(EmailOutboxRetryPolicy, TemporaryFailureRetriesUntilMaxAttempts) {
  EXPECT_FALSE(workers::ShouldMarkEmailOutboxDead(1, 3, true));
  EXPECT_FALSE(workers::ShouldMarkEmailOutboxDead(2, 3, true));
  EXPECT_TRUE(workers::ShouldMarkEmailOutboxDead(3, 3, true));
}

UTEST(EmailOutboxRetryPolicy, PermanentFailureIsDeadImmediately) {
  EXPECT_TRUE(workers::ShouldMarkEmailOutboxDead(1, 10, false));
}

}  // namespace
