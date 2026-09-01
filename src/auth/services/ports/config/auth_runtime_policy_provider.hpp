#pragma once

#include <auth/services/policies/auth_runtime_policies.hpp>

namespace smirkly::auth::services::ports::config {

class AuthRuntimePolicyProvider {
 public:
  virtual ~AuthRuntimePolicyProvider() = default;

  [[nodiscard]] virtual policies::AuthRuntimePolicies Get() const = 0;
};

}  // namespace smirkly::auth::services::ports::config
