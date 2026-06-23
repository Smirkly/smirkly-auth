#include <auth/config/runtime_config_providers.hpp>

#include <utility>

#include <auth/config/auth_dynamic_config.hpp>

namespace smirkly::auth::config {

DynamicConfigAuthRuntimePolicyProvider::DynamicConfigAuthRuntimePolicyProvider(
    userver::dynamic_config::Source source,
    services::policies::AuthRuntimePolicies fallback)
    : source_(std::move(source)), fallback_(std::move(fallback)) {}

services::policies::AuthRuntimePolicies
DynamicConfigAuthRuntimePolicyProvider::Get() const {
  auto policies = fallback_;

  const auto snapshot = source_.GetSnapshot();
  const auto& runtime = snapshot[kAuthRuntimeConfig];
  policies.sign_in = runtime.sign_in;
  policies.session.activity_update_threshold =
      runtime.session.activity_update_threshold;
  policies.email_verification = runtime.email_verification;

  return policies;
}

DynamicConfigEmailOutboxRuntimeConfigProvider::
    DynamicConfigEmailOutboxRuntimeConfigProvider(
        userver::dynamic_config::Source source)
    : source_(std::move(source)) {}

infra::workers::EmailOutboxRuntimeConfig
DynamicConfigEmailOutboxRuntimeConfigProvider::Get() const {
  const auto snapshot = source_.GetSnapshot();
  return snapshot[kEmailOutboxRuntimeConfig];
}

}  // namespace smirkly::auth::config
