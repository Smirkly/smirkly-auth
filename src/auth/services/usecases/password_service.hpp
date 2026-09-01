#pragma once

#include <auth/services/contracts/auth_context.hpp>
#include <auth/services/contracts/change_password.hpp>
#include <auth/services/contracts/password_reset.hpp>
#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/policies/password_policy.hpp>
#include <auth/services/policies/password_reset_policy.hpp>
#include <auth/services/ports/config/auth_runtime_policy_provider.hpp>
#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/repositories/password_reset_repository.hpp>
#include <auth/services/ports/repositories/session_repository.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/security/password_hasher.hpp>
#include <auth/services/ports/security/token_generator.hpp>
#include <auth/services/ports/security/token_hasher.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>
#include <auth/services/validation/password_validator.hpp>

namespace smirkly::auth::services::usecases {

class PasswordService final {
 public:
  PasswordService(ports::TransactionManager& transaction_manager,
                  ports::UserRepository& user_repo,
                  ports::PasswordResetRepository& password_reset_repo,
                  ports::EmailOutboxRepository& email_outbox_repo,
                  ports::SessionRepository& session_repo,
                  ports::PasswordHasher& password_hasher,
                  ports::security::TokenHasher& reset_token_hasher,
                  ports::security::TokenGenerator& reset_token_generator,
                  policies::PasswordPolicy password_policy = {},
                  policies::PasswordResetPolicy password_reset_policy = {},
                  const ports::config::AuthRuntimePolicyProvider*
                      runtime_policy_provider = nullptr);

  void ChangePassword(const contracts::AuthContext& context,
                      const contracts::ChangePasswordCommand& cmd);

  void RequestReset(const contracts::RequestPasswordResetCommand& cmd,
                    const contracts::RequestMeta& meta = {});

  void ConfirmReset(const contracts::ConfirmPasswordResetCommand& cmd,
                    const contracts::RequestMeta& meta = {});

 private:
  [[nodiscard]] policies::PasswordResetPolicy GetResetPolicy() const;

  ports::TransactionManager& transaction_manager_;
  ports::UserRepository& user_repo_;
  ports::PasswordResetRepository& password_reset_repo_;
  ports::EmailOutboxRepository& email_outbox_repo_;
  ports::SessionRepository& session_repo_;
  ports::PasswordHasher& password_hasher_;
  ports::security::TokenHasher& reset_token_hasher_;
  ports::security::TokenGenerator& reset_token_generator_;
  policies::PasswordResetPolicy password_reset_policy_;
  const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider_;
  validation::PasswordValidator password_validator_;
};

}  // namespace smirkly::auth::services::usecases
