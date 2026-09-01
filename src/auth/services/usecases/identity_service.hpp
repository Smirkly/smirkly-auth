#pragma once

#include <auth/services/contracts/auth_context.hpp>
#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/contracts/sign_up.hpp>
#include <auth/services/contracts/verify_email.hpp>
#include <auth/services/policies/email_verification_policy.hpp>
#include <auth/services/policies/sign_up_policy.hpp>
#include <auth/services/policies/sign_up_rate_limit_policy.hpp>
#include <auth/services/ports/config/auth_runtime_policy_provider.hpp>
#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/repositories/email_verification_repository.hpp>
#include <auth/services/ports/repositories/sign_up_attempt_repository.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/security/password_hasher.hpp>
#include <auth/services/ports/support/verification_code_generator.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>
#include <auth/services/validation/sign_up_validator.hpp>

namespace smirkly::auth::services::usecases {

class IdentityService final {
 public:
  IdentityService(
      ports::TransactionManager& transaction_manager,
      ports::UserRepository& user_repo,
      ports::EmailOutboxRepository& email_outbox_repo,
      ports::EmailVerificationRepository& email_verification_repo,
      ports::SignUpAttemptRepository& sign_up_attempt_repo,
      ports::PasswordHasher& password_hasher,
      ports::VerificationCodeGenerator& code_generator,
      policies::SignUpPolicy sign_up_policy = {},
      policies::SignUpRateLimitPolicy sign_up_rate_limit_policy = {},
      policies::EmailVerificationPolicy email_verification_policy = {},
      const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider =
          nullptr);

  contracts::SignUpResult SignUp(const contracts::SignUpCommand& cmd,
                                 const contracts::RequestMeta& meta = {});

  void VerifyEmail(const contracts::VerifyEmailCommand& cmd,
                   const contracts::RequestMeta& meta = {});

  void ResendEmailVerification(
      const contracts::ResendEmailVerificationCommand& cmd,
      const contracts::RequestMeta& meta = {});

  contracts::MeResult GetCurrentUser(
      const contracts::AuthContext& context) const;

 private:
  [[nodiscard]] policies::SignUpRateLimitPolicy GetSignUpPolicy() const;
  [[nodiscard]] policies::EmailVerificationPolicy GetEmailVerificationPolicy()
      const;

  ports::TransactionManager& transaction_manager_;
  ports::UserRepository& user_repo_;
  ports::EmailOutboxRepository& email_outbox_repo_;
  ports::EmailVerificationRepository& email_verification_repo_;
  ports::SignUpAttemptRepository& sign_up_attempt_repo_;
  ports::PasswordHasher& password_hasher_;
  ports::VerificationCodeGenerator& code_generator_;
  policies::SignUpRateLimitPolicy sign_up_rate_limit_policy_;
  policies::EmailVerificationPolicy email_verification_policy_;
  const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider_;
  validation::SignUpValidator sign_up_validator_;
};

}  // namespace smirkly::auth::services::usecases
