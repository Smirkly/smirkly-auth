#include <auth/services/usecases/password_service.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>

#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/change_password_errors.hpp>
#include <auth/services/errors/password_reset_errors.hpp>
#include <auth/services/factories/email_outbox_factory.hpp>

namespace smirkly::auth::services::usecases {

PasswordService::PasswordService(
    ports::TransactionManager& transaction_manager,
    ports::UserRepository& user_repo,
    ports::PasswordResetRepository& password_reset_repo,
    ports::EmailOutboxRepository& email_outbox_repo,
    ports::SessionRepository& session_repo,
    ports::PasswordHasher& password_hasher,
    ports::security::TokenHasher& reset_token_hasher,
    ports::security::TokenGenerator& reset_token_generator,
    policies::PasswordPolicy password_policy,
    policies::PasswordResetPolicy password_reset_policy,
    const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider)
    : transaction_manager_(transaction_manager),
      user_repo_(user_repo),
      password_reset_repo_(password_reset_repo),
      email_outbox_repo_(email_outbox_repo),
      session_repo_(session_repo),
      password_hasher_(password_hasher),
      reset_token_hasher_(reset_token_hasher),
      reset_token_generator_(reset_token_generator),
      password_reset_policy_(password_reset_policy),
      runtime_policy_provider_(runtime_policy_provider),
      password_validator_(password_policy) {}

policies::PasswordResetPolicy PasswordService::GetResetPolicy() const {
  if (runtime_policy_provider_) {
    return runtime_policy_provider_->Get().password_reset;
  }
  return password_reset_policy_;
}

void PasswordService::ChangePassword(
    const contracts::AuthContext& context,
    const contracts::ChangePasswordCommand& cmd) {
  if (cmd.current_password.empty()) {
    throw errors::ChangePasswordValidation("current password is required");
  }

  try {
    password_validator_.Validate(cmd.new_password);
  } catch (const std::invalid_argument& e) {
    throw errors::ChangePasswordValidation(e.what());
  }

  const auto user_opt =
      user_repo_.FindById(context.user_id, ports::ReadConsistency::kStrong);
  if (!user_opt) {
    throw errors::AuthUserNotFound("user not found");
  }

  if (!password_hasher_.Verify(cmd.current_password, user_opt->password)) {
    throw errors::InvalidCurrentPassword("invalid current password");
  }
  if (password_hasher_.Verify(cmd.new_password, user_opt->password)) {
    throw errors::ChangePasswordValidation(
        "new password must differ from current password");
  }

  const auto new_password_hash = password_hasher_.Hash(cmd.new_password);
  auto tx = transaction_manager_.Begin("auth.change_password");
  user_repo_.UpdatePasswordHash(*tx, context.user_id, new_password_hash);
  session_repo_.RevokeAllByUserId(*tx, context.user_id);
  tx->Commit();
}

void PasswordService::RequestReset(
    const contracts::RequestPasswordResetCommand& cmd,
    const contracts::RequestMeta& meta) {
  const auto policy = GetResetPolicy();
  const auto now = std::chrono::system_clock::now();
  const auto user_opt =
      user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

  std::optional<std::string> user_id;
  if (user_opt) {
    user_id = user_opt->id;
  }

  const auto since = now - policy.rate_limit_window;
  auto tx = transaction_manager_.Begin("auth.password_reset.request");
  if (!password_reset_repo_.TryRecordAttempt(
          *tx, cmd.email, user_id, meta.ip, meta.user_agent, now, since,
          policy.max_attempts_per_email, policy.max_attempts_per_user,
          policy.max_attempts_per_ip)) {
    throw errors::TooManyPasswordResetAttempts(
        "too many password reset attempts");
  }

  if (user_opt && user_opt->email) {
    password_reset_repo_.MarkActiveUsedByUserId(*tx, user_opt->id, now);

    const std::string raw_token = reset_token_generator_.Generate();
    const std::string token_hash = reset_token_hasher_.Hash(raw_token);
    const auto reset = password_reset_repo_.Insert(
        *tx, ports::NewPasswordResetData{
                 .user_id = user_opt->id,
                 .token_hash = token_hash,
                 .expires_at = now + policy.token_ttl,
                 .ip = meta.ip,
                 .user_agent = meta.user_agent,
             });

    auto job = factories::EmailOutboxFactory::PasswordResetEmail(
        *user_opt->email, raw_token, reset.id, "ru");
    email_outbox_repo_.Insert(*tx, job);
  }

  tx->Commit();
}

void PasswordService::ConfirmReset(
    const contracts::ConfirmPasswordResetCommand& cmd,
    const contracts::RequestMeta& meta) {
  try {
    password_validator_.Validate(cmd.new_password);
  } catch (const std::invalid_argument& e) {
    throw errors::PasswordResetValidation(e.what());
  }

  const auto policy = GetResetPolicy();
  const auto now = std::chrono::system_clock::now();
  const auto user_opt =
      user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

  std::optional<std::string> user_id;
  if (user_opt) {
    user_id = user_opt->id;
  }

  const auto since = now - policy.rate_limit_window;
  {
    auto tx = transaction_manager_.Begin(
        "auth.password_reset.confirm.record_attempt");
    if (!password_reset_repo_.TryRecordAttempt(
            *tx, cmd.email, user_id, meta.ip, meta.user_agent, now, since,
            policy.max_attempts_per_email, policy.max_attempts_per_user,
            policy.max_attempts_per_ip)) {
      throw errors::TooManyPasswordResetAttempts(
          "too many password reset attempts");
    }
    tx->Commit();
  }

  if (!user_opt) {
    throw errors::InvalidPasswordResetToken("invalid password reset token");
  }

  const auto reset_opt = password_reset_repo_.FindActiveByUserId(
      user_opt->id, now, policy.max_token_attempts);
  if (!reset_opt) {
    throw errors::PasswordResetExpired(
        "password reset token expired or not found");
  }

  const auto& reset = *reset_opt;
  if (!reset_token_hasher_.Verify(cmd.token, reset.token_hash)) {
    auto tx = transaction_manager_.Begin("auth.password_reset.invalid_token");
    password_reset_repo_.IncrementAttempts(*tx, reset.id, now,
                                           policy.max_token_attempts);
    tx->Commit();
    throw errors::InvalidPasswordResetToken("invalid password reset token");
  }

  if (password_hasher_.Verify(cmd.new_password, user_opt->password)) {
    throw errors::PasswordResetValidation(
        "new password must differ from current password");
  }

  const auto new_password_hash = password_hasher_.Hash(cmd.new_password);
  auto tx = transaction_manager_.Begin("auth.password_reset.confirm");
  if (!password_reset_repo_.MarkUsed(*tx, reset.id, now,
                                     policy.max_token_attempts)) {
    throw errors::InvalidPasswordResetToken(
        "password reset token expired, exhausted, or already used");
  }
  user_repo_.UpdatePasswordHash(*tx, user_opt->id, new_password_hash);
  session_repo_.RevokeAllByUserId(*tx, user_opt->id);
  tx->Commit();
}

}  // namespace smirkly::auth::services::usecases
