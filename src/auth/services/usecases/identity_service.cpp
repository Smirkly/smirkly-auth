#include <auth/services/usecases/identity_service.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/factories/email_outbox_factory.hpp>
#include <auth/services/factories/email_verification_factory.hpp>
#include <auth/services/factories/user_factory.hpp>

namespace smirkly::auth::services::usecases {

IdentityService::IdentityService(
    ports::TransactionManager& transaction_manager,
    ports::UserRepository& user_repo,
    ports::EmailOutboxRepository& email_outbox_repo,
    ports::EmailVerificationRepository& email_verification_repo,
    ports::SignUpAttemptRepository& sign_up_attempt_repo,
    ports::PasswordHasher& password_hasher,
    ports::VerificationCodeGenerator& code_generator,
    policies::SignUpPolicy sign_up_policy,
    policies::SignUpRateLimitPolicy sign_up_rate_limit_policy,
    policies::EmailVerificationPolicy email_verification_policy,
    const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider)
    : transaction_manager_(transaction_manager),
      user_repo_(user_repo),
      email_outbox_repo_(email_outbox_repo),
      email_verification_repo_(email_verification_repo),
      sign_up_attempt_repo_(sign_up_attempt_repo),
      password_hasher_(password_hasher),
      code_generator_(code_generator),
      sign_up_rate_limit_policy_(sign_up_rate_limit_policy),
      email_verification_policy_(email_verification_policy),
      runtime_policy_provider_(runtime_policy_provider),
      sign_up_validator_(std::move(sign_up_policy)) {}

policies::SignUpRateLimitPolicy IdentityService::GetSignUpPolicy() const {
  if (runtime_policy_provider_) {
    return runtime_policy_provider_->Get().sign_up;
  }
  return sign_up_rate_limit_policy_;
}

policies::EmailVerificationPolicy IdentityService::GetEmailVerificationPolicy()
    const {
  if (runtime_policy_provider_) {
    return runtime_policy_provider_->Get().email_verification;
  }
  return email_verification_policy_;
}

contracts::SignUpResult IdentityService::SignUp(
    const contracts::SignUpCommand& cmd, const contracts::RequestMeta& meta) {
  const auto sign_up_policy = GetSignUpPolicy();
  const auto email_verification_policy = GetEmailVerificationPolicy();
  const auto input = sign_up_validator_.ValidateAndNormalize(cmd);
  const auto& normalized_username = input.username.Value();

  if (meta.ip && sign_up_policy.max_attempts_per_ip > 0) {
    const auto now = std::chrono::system_clock::now();
    auto tx = transaction_manager_.Begin("auth.sign_up.rate_limit");
    if (!sign_up_attempt_repo_.TryRecordAttempt(
            *tx, *meta.ip, now, now - sign_up_policy.window,
            sign_up_policy.max_attempts_per_ip)) {
      throw errors::TooManySignUpAttempts("too many sign-up attempts");
    }
    tx->Commit();
  }

  if (user_repo_.ExistsByUsername(normalized_username)) {
    throw errors::UsernameTaken("username taken");
  }
  if (input.email && user_repo_.ExistsByEmail(input.email->Value())) {
    throw errors::EmailTaken("email taken");
  }
  if (input.phone && user_repo_.ExistsByPhone(input.phone->Value())) {
    throw errors::PhoneTaken("phone taken");
  }

  const std::string password_hash = password_hasher_.Hash(input.password);

  std::optional<std::string> email;
  if (input.email) {
    email = input.email->Value();
  }

  std::optional<std::string> phone;
  if (input.phone) {
    phone = input.phone->Value();
  }

  auto new_user_data = factories::UserFactory::CreateFromSignUp(
      normalized_username, password_hash, std::move(email), std::move(phone));

  auto tx = transaction_manager_.Begin("auth.sign_up");
  domain::models::User user = user_repo_.Insert(*tx, new_user_data);

  if (user.email) {
    const std::string raw_code = code_generator_.Generate();
    const std::string code_hash = password_hasher_.Hash(raw_code);
    const auto now = std::chrono::system_clock::now();

    auto verification_data = factories::EmailVerificationFactory::Create(
        user.id, code_hash, meta, now, email_verification_policy.code_ttl);
    email_verification_repo_.Insert(*tx, verification_data);

    auto job = factories::EmailOutboxFactory::VerificationEmail(
        *user.email, raw_code, user.id, "ru");
    email_outbox_repo_.Insert(*tx, job);
  }

  tx->Commit();
  return {std::move(user)};
}

void IdentityService::VerifyEmail(const contracts::VerifyEmailCommand& cmd,
                                  const contracts::RequestMeta& meta) {
  const auto policy = GetEmailVerificationPolicy();
  const auto now = std::chrono::system_clock::now();
  const auto user_opt =
      user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

  if (user_opt && user_opt->is_email_verified) {
    throw errors::AlreadyVerified("User already verified");
  }

  std::optional<std::string> user_id;
  if (user_opt) {
    user_id = user_opt->id;
  }

  const auto since = now - policy.rate_limit_window;
  {
    auto tx = transaction_manager_.Begin("auth.verify_email.record_attempt");
    if (!email_verification_repo_.TryRecordAttempt(
            *tx, cmd.email, user_id, meta.ip, meta.user_agent, now, since,
            policy.max_attempts_per_email, policy.max_attempts_per_user,
            policy.max_attempts_per_ip)) {
      throw errors::TooManyVerificationAttempts(
          "too many verification attempts");
    }
    tx->Commit();
  }

  if (!user_opt) {
    throw errors::UserNotFound("User not found");
  }

  const auto verification_opt = email_verification_repo_.FindActiveByUserId(
      user_opt->id, now, policy.max_code_attempts);
  if (!verification_opt) {
    throw errors::CodeExpired("Verification code expired or not found");
  }

  const auto& verification = *verification_opt;
  if (!password_hasher_.Verify(cmd.code, verification.code_hash)) {
    auto tx = transaction_manager_.Begin("auth.verify_email.invalid_code");
    email_verification_repo_.IncrementAttempts(*tx, verification.id, now,
                                               policy.max_code_attempts);
    tx->Commit();
    throw errors::InvalidCode("Invalid verification code");
  }

  auto tx = transaction_manager_.Begin("auth.verify_email");
  if (!email_verification_repo_.MarkUsed(*tx, verification.id, now,
                                         policy.max_code_attempts)) {
    throw errors::CodeExpired(
        "Verification code expired, exhausted, or already used");
  }
  user_repo_.SetEmailVerified(*tx, user_opt->id, true);
  tx->Commit();
}

void IdentityService::ResendEmailVerification(
    const contracts::ResendEmailVerificationCommand& cmd,
    const contracts::RequestMeta& meta) {
  const auto policy = GetEmailVerificationPolicy();
  const auto now = std::chrono::system_clock::now();
  const auto user_opt =
      user_repo_.FindByEmail(cmd.email, ports::ReadConsistency::kStrong);

  std::optional<std::string> user_id;
  if (user_opt) {
    user_id = user_opt->id;
  }

  const auto since = now - policy.rate_limit_window;
  auto tx = transaction_manager_.Begin("auth.resend_email_verification");
  if (!email_verification_repo_.TryRecordAttempt(
          *tx, cmd.email, user_id, meta.ip, meta.user_agent, now, since,
          policy.max_attempts_per_email, policy.max_attempts_per_user,
          policy.max_attempts_per_ip)) {
    throw errors::TooManyVerificationAttempts("too many verification attempts");
  }

  if (user_opt && !user_opt->is_email_verified && user_opt->email) {
    email_verification_repo_.MarkActiveUsedByUserId(*tx, user_opt->id, now);

    const std::string raw_code = code_generator_.Generate();
    const std::string code_hash = password_hasher_.Hash(raw_code);
    auto verification_data = factories::EmailVerificationFactory::Create(
        user_opt->id, code_hash, meta, now, policy.code_ttl);
    email_verification_repo_.Insert(*tx, verification_data);

    auto job = factories::EmailOutboxFactory::VerificationEmail(
        *user_opt->email, raw_code, user_opt->id, "ru");
    email_outbox_repo_.Insert(*tx, job);
  }

  tx->Commit();
}

contracts::MeResult IdentityService::GetCurrentUser(
    const contracts::AuthContext& context) const {
  const auto user_opt =
      user_repo_.FindById(context.user_id, ports::ReadConsistency::kStrong);
  if (!user_opt) {
    throw errors::AuthUserNotFound("user not found");
  }

  return {
      .user = *user_opt,
      .session_id = context.session_id,
  };
}

}  // namespace smirkly::auth::services::usecases
