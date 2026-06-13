#pragma once

#include <userver/components/component_config.hpp>

#include <auth/services/policies/email_verification_policy.hpp>
#include <auth/services/policies/session_policy.hpp>
#include <auth/services/policies/sign_in_policy.hpp>

namespace smirkly::auth::config {
    struct AuthServiceSettings final {
        services::policies::SessionPolicy session;
        services::policies::SignInPolicy sign_in;
        services::policies::EmailVerificationPolicy email_verification;
    };

    AuthServiceSettings ParseAuthServiceSettings(
        const userver::components::ComponentConfig &cfg);
}
