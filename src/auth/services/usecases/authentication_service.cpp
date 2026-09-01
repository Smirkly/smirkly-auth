#include <auth/services/usecases/authentication_service.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/refresh_errors.hpp>
#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/factories/device_factory.hpp>
#include <auth/services/factories/session_factory.hpp>
#include <auth/services/policies/rate_limit_policy.hpp>
#include <auth/services/policies/session_activity_policy.hpp>

namespace smirkly::auth::services::usecases {

AuthenticationService::AuthenticationService(
    ports::TransactionManager& transaction_manager,
    ports::UserRepository& user_repo,
    ports::SignInAttemptRepository& sign_in_attempt_repo,
    ports::PasswordHasher& password_hasher,
    ports::security::TokenHasher& refresh_token_hasher,
    ports::security::JwtTokenProvider& token_provider,
    ports::DeviceRepository& device_repo,
    ports::SessionRepository& session_repo,
    ports::support::IdGenerator& id_generator,
    policies::SessionPolicy session_policy,
    policies::SignInPolicy sign_in_policy,
    const ports::config::AuthRuntimePolicyProvider* runtime_policy_provider)
    : transaction_manager_(transaction_manager),
      user_repo_(user_repo),
      sign_in_attempt_repo_(sign_in_attempt_repo),
      password_hasher_(password_hasher),
      refresh_token_hasher_(refresh_token_hasher),
      token_provider_(token_provider),
      device_repo_(device_repo),
      session_repo_(session_repo),
      id_generator_(id_generator),
      session_policy_(session_policy),
      sign_in_policy_(sign_in_policy),
      runtime_policy_provider_(runtime_policy_provider) {
  if (session_policy_.refresh_token_ttl <= std::chrono::seconds{0}) {
    throw std::runtime_error("session refresh token TTL must be positive");
  }
  if (session_policy_.activity_update_threshold < std::chrono::seconds{0}) {
    throw std::runtime_error(
        "session activity update threshold must not be negative");
  }
}

policies::SessionPolicy AuthenticationService::GetSessionPolicy() const {
  if (runtime_policy_provider_) {
    return runtime_policy_provider_->Get().session;
  }
  return session_policy_;
}

policies::SignInPolicy AuthenticationService::GetSignInPolicy() const {
  if (runtime_policy_provider_) {
    return runtime_policy_provider_->Get().sign_in;
  }
  return sign_in_policy_;
}

contracts::SignInResult AuthenticationService::SignIn(
    const contracts::SignInCommand& cmd, const contracts::RequestMeta& meta) {
  const auto sign_in_policy = GetSignInPolicy();
  const auto session_policy = GetSessionPolicy();
  const auto input = sign_in_validator_.ValidateAndNormalize(cmd);
  const auto now = std::chrono::system_clock::now();
  const auto& login_identifier = input.rate_limit_identifier;

  std::optional<domain::models::User> user_opt;
  if (input.username) {
    user_opt = user_repo_.FindByUsername(*input.username,
                                         ports::ReadConsistency::kStrong);
  } else if (input.email) {
    user_opt =
        user_repo_.FindByEmail(*input.email, ports::ReadConsistency::kStrong);
  } else if (input.phone) {
    user_opt =
        user_repo_.FindByPhone(*input.phone, ports::ReadConsistency::kStrong);
  }

  std::optional<std::string> user_id;
  if (user_opt) {
    user_id = user_opt->id;
  }

  const auto since = now - sign_in_policy.rate_limit_window;
  const auto counters = sign_in_attempt_repo_.CountRecentAttempts(
      login_identifier, user_id, meta.ip, since);

  if (policies::IsRateLimitExceeded(
          counters.identifier, sign_in_policy.max_attempts_per_identifier) ||
      policies::IsRateLimitExceeded(counters.user,
                                    sign_in_policy.max_attempts_per_user) ||
      policies::IsRateLimitExceeded(counters.ip,
                                    sign_in_policy.max_attempts_per_ip)) {
    throw errors::TooManySignInAttempts("too many sign-in attempts");
  }

  const auto record_failed_attempt = [&] {
    auto tx = transaction_manager_.Begin("auth.sign_in.record_attempt");
    if (!sign_in_attempt_repo_.TryRecordAttempt(
            *tx, login_identifier, user_id, meta.ip, meta.user_agent, now,
            since, sign_in_policy.max_attempts_per_identifier,
            sign_in_policy.max_attempts_per_user,
            sign_in_policy.max_attempts_per_ip)) {
      throw errors::TooManySignInAttempts("too many sign-in attempts");
    }
    tx->Commit();
  };

  if (!user_opt) {
    record_failed_attempt();
    throw errors::InvalidCredentials("invalid credentials");
  }
  const auto& user = *user_opt;

  if (!password_hasher_.Verify(cmd.password, user.password)) {
    record_failed_attempt();
    throw errors::InvalidCredentials("invalid credentials");
  }

  if (sign_in_policy.require_verified_email && user.email.has_value() &&
      !user.is_email_verified) {
    record_failed_attempt();
    throw errors::EmailNotVerified("email is not verified");
  }

  const std::string session_id = id_generator_.Generate();
  const std::string token_family_id = id_generator_.Generate();
  auto tokens =
      token_provider_.GenerateTokens(user.id, session_id, token_family_id);
  auto refresh_token_hash = refresh_token_hasher_.Hash(tokens.refresh_token);

  auto tx = transaction_manager_.Begin("auth.sign_in");
  auto new_device_data = factories::DeviceFactory::WebDevice(user.id, meta);
  auto device = device_repo_.Insert(*tx, new_device_data);
  auto new_session_data = factories::SessionFactory::CreateForSignIn(
      session_id, user.id, device.id, std::move(refresh_token_hash),
      token_family_id, meta, session_policy.refresh_token_ttl);
  domain::models::Session session = session_repo_.Insert(*tx, new_session_data);
  tx->Commit();

  return {
      .user = user,
      .tokens = std::move(tokens),
      .session_id = session.id,
      .refresh_token_max_age = session_policy.refresh_token_ttl,
  };
}

contracts::RefreshResult AuthenticationService::Refresh(
    const contracts::RefreshCommand& cmd, const contracts::RequestMeta& meta) {
  const auto session_policy = GetSessionPolicy();
  if (cmd.refresh_token.empty()) {
    throw errors::InvalidRefreshToken("refresh token is empty");
  }

  const auto claims = token_provider_.ParseRefreshToken(cmd.refresh_token);
  const auto session_opt = session_repo_.FindById(
      claims.session_id, ports::ReadConsistency::kStrong);
  if (!session_opt) {
    throw errors::RefreshSessionNotFound("session not found");
  }

  const auto session = *session_opt;
  const auto now = std::chrono::system_clock::now();
  if (session.user_id != claims.user_id) {
    throw errors::InvalidRefreshToken("refresh token subject mismatch");
  }
  if (!claims.token_family_id ||
      *claims.token_family_id != session.token_family_id) {
    throw errors::InvalidRefreshToken("refresh token family mismatch");
  }

  if (session.revoked_at.has_value()) {
    const bool reused_refresh_token = refresh_token_hasher_.Verify(
        cmd.refresh_token, session.refresh_token_hash);
    if (reused_refresh_token) {
      auto tx = transaction_manager_.Begin("auth.refresh.reuse_detected");
      session_repo_.RevokeByTokenFamily(*tx, session.user_id,
                                        session.token_family_id);
      tx->Commit();
      throw errors::RefreshTokenReuseDetected("refresh token reuse detected");
    }
    throw errors::RefreshSessionRevoked("session revoked");
  }

  if (session.expires_at <= now) {
    throw errors::RefreshSessionExpired("session expired");
  }
  if (!refresh_token_hasher_.Verify(cmd.refresh_token,
                                    session.refresh_token_hash)) {
    throw errors::InvalidRefreshToken("refresh token hash mismatch");
  }

  const std::string new_session_id = id_generator_.Generate();
  auto tokens = token_provider_.GenerateTokens(session.user_id, new_session_id,
                                               session.token_family_id);
  auto new_refresh_token_hash =
      refresh_token_hasher_.Hash(tokens.refresh_token);
  auto replacement_session_data =
      factories::SessionFactory::CreateForRefreshRotation(
          new_session_id, session, std::move(new_refresh_token_hash), meta,
          session_policy.refresh_token_ttl);

  auto tx = transaction_manager_.Begin("auth.refresh");
  const auto replacement_session =
      session_repo_.Insert(*tx, replacement_session_data);
  if (!session_repo_.RevokeAndReplace(*tx, session.id,
                                      replacement_session.id)) {
    throw errors::RefreshSessionRevoked("session already rotated");
  }
  tx->Commit();

  return {
      .access_token = std::move(tokens.access_token),
      .refresh_token = std::move(tokens.refresh_token),
      .session_id = replacement_session.id,
      .refresh_token_max_age = session_policy.refresh_token_ttl,
  };
}

contracts::AuthContext AuthenticationService::AuthenticateAccessToken(
    std::string_view access_token) {
  const auto session_policy = GetSessionPolicy();
  if (access_token.empty()) {
    throw errors::MissingAccessToken("access token is required");
  }

  const auto claims = token_provider_.ParseAccessToken(access_token);
  const auto session_opt = session_repo_.FindById(
      claims.session_id, ports::ReadConsistency::kStrong);
  if (!session_opt) {
    throw errors::AuthSessionNotFound("session not found");
  }

  const auto& session = *session_opt;
  if (session.user_id != claims.user_id) {
    throw errors::InvalidAccessToken("access token subject mismatch");
  }
  if (session.revoked_at) {
    throw errors::AuthSessionRevoked("session revoked");
  }

  const auto now = std::chrono::system_clock::now();
  if (session.expires_at <= now) {
    throw errors::AuthSessionExpired("session expired");
  }

  const auto user_opt =
      user_repo_.FindById(claims.user_id, ports::ReadConsistency::kStrong);
  if (!user_opt) {
    throw errors::AuthUserNotFound("user not found");
  }

  if (policies::ShouldUpdateLastUsed(
          session, now, session_policy.activity_update_threshold)) {
    auto tx = transaction_manager_.Begin("auth.session_activity");
    session_repo_.UpdateLastUsed(*tx, session.id, now);
    tx->Commit();
  }

  return {
      .user_id = claims.user_id,
      .session_id = claims.session_id,
  };
}

}  // namespace smirkly::auth::services::usecases
