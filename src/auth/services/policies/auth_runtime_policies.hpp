#pragma once

#include <auth/services/policies/email_verification_policy.hpp>
#include <auth/services/policies/session_policy.hpp>
#include <auth/services/policies/sign_in_policy.hpp>

namespace smirkly::auth::services::policies {

struct AuthRuntimePolicies final {
  SessionPolicy session;
  SignInPolicy sign_in;
  EmailVerificationPolicy email_verification;
};

}  // namespace smirkly::auth::services::policies
