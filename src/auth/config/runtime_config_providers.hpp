#pragma once

#include <userver/dynamic_config/source.hpp>

#include <auth/infra/workers/email_outbox_runtime_config_provider.hpp>
#include <auth/services/ports/config/auth_runtime_policy_provider.hpp>

namespace smirkly::auth::config {

class DynamicConfigAuthRuntimePolicyProvider final
    : public services::ports::config::AuthRuntimePolicyProvider {
 public:
  DynamicConfigAuthRuntimePolicyProvider(
      userver::dynamic_config::Source source,
      services::policies::AuthRuntimePolicies fallback);

  [[nodiscard]] services::policies::AuthRuntimePolicies Get() const override;

 private:
  userver::dynamic_config::Source source_;
  services::policies::AuthRuntimePolicies fallback_;
};

class DynamicConfigEmailOutboxRuntimeConfigProvider final
    : public infra::workers::EmailOutboxRuntimeConfigProvider {
 public:
  explicit DynamicConfigEmailOutboxRuntimeConfigProvider(
      userver::dynamic_config::Source source);

  [[nodiscard]] infra::workers::EmailOutboxRuntimeConfig Get() const override;

 private:
  userver::dynamic_config::Source source_;
};

}  // namespace smirkly::auth::config
