#pragma once

#include <string_view>

#include <auth/services/contracts/auth_context.hpp>
#include <auth/services/contracts/refresh.hpp>
#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/contracts/sign_in.hpp>
#include <auth/services/policies/session_policy.hpp>
#include <auth/services/policies/sign_in_policy.hpp>
#include <auth/services/ports/config/auth_runtime_policy_provider.hpp>
#include <auth/services/ports/repositories/device_repository.hpp>
#include <auth/services/ports/repositories/session_repository.hpp>
#include <auth/services/ports/repositories/sign_in_attempt_repository.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/security/jwt_token_provider.hpp>
#include <auth/services/ports/security/password_hasher.hpp>
#include <auth/services/ports/security/token_hasher.hpp>
#include <auth/services/ports/support/id_generator.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>
#include <auth/services/validation/sign_in_validator.hpp>

namespace smirkly::auth::services::usecases {

class AuthenticationService final {
 public:
  AuthenticationService(ports::TransactionManager& transaction_manager,
                        ports::UserRepository& user_repo,
                        ports::SignInAttemptRepository& sign_in_attempt_repo,
                        ports::PasswordHasher& password_hasher,
                        ports::security::TokenHasher& refresh_token_hasher,
                        ports::security::JwtTokenProvider& token_provider,
                        ports::DeviceRepository& device_repo,
                        ports::SessionRepository& session_repo,
                        ports::support::IdGenerator& id_generator,
                        policies::SessionPolicy session_policy,
                        policies::SignInPolicy sign_in_policy = {},
                        const ports::config::AuthRuntimePolicyProvider*
                            runtime_policy_provider = nullptr);

  contracts::SignInResult SignIn(const contracts::SignInCommand& cmd,
                                 const contracts::RequestMeta& meta = {});

  contracts::RefreshResult Refresh(const contracts::RefreshCommand& cmd,
                                   const contracts::RequestMeta& meta = {});

  contracts::AuthContext AuthenticateAccessToken(std::string_view access_token);

 private:
  [[nodiscard]] policies::SessionPolicy GetSessionPolicy() const;
  [[nodiscard]] policies::SignInPolicy GetSignInPolicy() const;

  ports::TransactionManager& transaction_manager_;
  ports::UserRepository& user_repo_;
  ports::SignInAttemptRepository& sign_in_attempt_repo_;
  ports::PasswordHasher& password_hasher_;
  ports::security::TokenHasher& refresh_token_hasher_;
  ports::security::JwtTokenProvider& token_provider_;
  ports::DeviceRepository& device_repo_;
  ports::SessionRepository& session_repo_;
  ports::support::IdGenerator& id_generator_;
  policies::SessionPolicy session_policy_;
  policies::SignInPolicy sign_in_policy_;
  const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider_;
  validation::SignInValidator sign_in_validator_;
};

}  // namespace smirkly::auth::services::usecases
