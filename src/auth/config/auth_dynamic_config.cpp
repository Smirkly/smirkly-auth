#include <auth/config/auth_dynamic_config.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

#include <userver/dynamic_config/value.hpp>

namespace smirkly::auth {
namespace {

std::size_t ParseSize(const userver::formats::json::Value& value,
                      std::string_view field, std::size_t default_value,
                      std::size_t min_value) {
  const auto parsed = value[std::string{field}].As<std::int64_t>(
      static_cast<std::int64_t>(default_value));
  if (parsed < 0) {
    throw std::runtime_error(std::string{field} + " must not be negative");
  }
  const auto as_uint = static_cast<std::uint64_t>(parsed);
  if (as_uint > static_cast<std::uint64_t>(
                    std::numeric_limits<std::size_t>::max())) {
    throw std::runtime_error(std::string{field} + " is too large");
  }
  const auto result = static_cast<std::size_t>(as_uint);
  if (result < min_value) {
    throw std::runtime_error(std::string{field} + " is below minimum");
  }
  return result;
}

std::chrono::seconds ParseSeconds(const userver::formats::json::Value& value,
                                  std::string_view field,
                                  std::chrono::seconds default_value,
                                  std::chrono::seconds min_value) {
  const auto parsed = value[std::string{field}].As<std::int64_t>(
      default_value.count());
  const auto result = std::chrono::seconds{parsed};
  if (result < min_value) {
    throw std::runtime_error(std::string{field} + " is below minimum");
  }
  return result;
}

}  // namespace

namespace services::policies {

AuthRuntimePolicies Parse(
    const userver::formats::json::Value& value,
    userver::formats::parse::To<AuthRuntimePolicies>) {
  AuthRuntimePolicies config;

  const auto sign_in = value["sign_in"];
  config.sign_in.require_verified_email =
      sign_in["require_verified_email"].As<bool>(
          config.sign_in.require_verified_email);

  const auto session_activity = value["session_activity"];
  config.session.activity_update_threshold = ParseSeconds(
      session_activity, "update_threshold_seconds",
      config.session.activity_update_threshold, std::chrono::seconds{0});

  const auto email_verification = value["email_verification"];
  auto& policy = config.email_verification;
  policy.code_ttl =
      ParseSeconds(email_verification, "code_ttl_seconds", policy.code_ttl,
                   std::chrono::seconds{1});
  policy.max_code_attempts =
      ParseSize(email_verification, "max_code_attempts",
                policy.max_code_attempts, 1);
  policy.rate_limit_window =
      ParseSeconds(email_verification, "rate_limit_window_seconds",
                   policy.rate_limit_window, std::chrono::seconds{1});
  policy.max_attempts_per_email =
      ParseSize(email_verification, "max_attempts_per_email",
                policy.max_attempts_per_email, 0);
  policy.max_attempts_per_user =
      ParseSize(email_verification, "max_attempts_per_user",
                policy.max_attempts_per_user, 0);
  policy.max_attempts_per_ip =
      ParseSize(email_verification, "max_attempts_per_ip",
                policy.max_attempts_per_ip, 0);

  return config;
}

}  // namespace services::policies

namespace infra::workers {

EmailOutboxRuntimeConfig Parse(
    const userver::formats::json::Value& value,
    userver::formats::parse::To<EmailOutboxRuntimeConfig>) {
  EmailOutboxRuntimeConfig config;

  config.processing_enabled =
      value["processing_enabled"].As<bool>(config.processing_enabled);
  config.batch_size = ParseSize(value, "batch_size", config.batch_size, 1);
  config.max_attempts = ParseSize(value, "max_attempts", config.max_attempts, 1);
  config.stuck_timeout =
      ParseSeconds(value, "stuck_timeout_seconds", config.stuck_timeout,
                   std::chrono::seconds{1});
  config.retry_base_delay =
      ParseSeconds(value, "retry_base_delay_seconds", config.retry_base_delay,
                   std::chrono::seconds{1});
  config.retry_max_delay =
      ParseSeconds(value, "retry_max_delay_seconds", config.retry_max_delay,
                   config.retry_base_delay);

  return config;
}

}  // namespace infra::workers

namespace config {

const userver::dynamic_config::Key<AuthRuntimeConfig> kAuthRuntimeConfig{
    "SMIRKLY_AUTH_RUNTIME_CONFIG",
    userver::dynamic_config::DefaultAsJsonString{R"({
      "sign_in": {
        "require_verified_email": false
      },
      "session_activity": {
        "update_threshold_seconds": 300
      },
      "email_verification": {
        "code_ttl_seconds": 900,
        "max_code_attempts": 5,
        "rate_limit_window_seconds": 900,
        "max_attempts_per_email": 5,
        "max_attempts_per_user": 5,
        "max_attempts_per_ip": 50
      }
    })"}};

const userver::dynamic_config::Key<EmailOutboxRuntimeConfig>
    kEmailOutboxRuntimeConfig{
        "SMIRKLY_EMAIL_OUTBOX_RUNTIME_CONFIG",
        userver::dynamic_config::DefaultAsJsonString{R"({
          "processing_enabled": true,
          "batch_size": 20,
          "max_attempts": 10,
          "stuck_timeout_seconds": 300,
          "retry_base_delay_seconds": 2,
          "retry_max_delay_seconds": 600
        })"}};

}  // namespace config
}  // namespace smirkly::auth
