#include <auth/config/auth_service_config.hpp>

#include <chrono>
#include <cstdint>

namespace smirkly::auth::config {
    AuthServiceSettings ParseAuthServiceSettings(
        const userver::components::ComponentConfig &cfg) {
        AuthServiceSettings settings;

        const auto session_activity = cfg["session-activity"];
        settings.session.activity_update_threshold = std::chrono::seconds{
            session_activity["update-threshold-seconds"].As<std::int64_t>(
                settings.session.activity_update_threshold.count())};

        const auto email_verification = cfg["email-verification"];
        auto &policy = settings.email_verification;

        const auto sign_in = cfg["sign-in"];
        settings.sign_in.require_verified_email =
            sign_in["require-verified-email"].As<bool>(
                settings.sign_in.require_verified_email);

        policy.max_code_attempts =
            email_verification["max-code-attempts"].As<std::size_t>(policy.max_code_attempts);
        policy.rate_limit_window = std::chrono::seconds{
            email_verification["rate-limit-window-seconds"].As<std::int64_t>(
                policy.rate_limit_window.count())};
        policy.max_attempts_per_email =
            email_verification["max-attempts-per-email"].As<std::size_t>(
                policy.max_attempts_per_email);
        policy.max_attempts_per_user =
            email_verification["max-attempts-per-user"].As<std::size_t>(
                policy.max_attempts_per_user);
        policy.max_attempts_per_ip =
            email_verification["max-attempts-per-ip"].As<std::size_t>(
                policy.max_attempts_per_ip);

        return settings;
    }
}
