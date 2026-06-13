#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/change_password_errors.hpp>
#include <auth/services/errors/refresh_errors.hpp>
#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/usecases/auth_service.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <userver/utest/utest.hpp>

namespace {
namespace auth = smirkly::auth;
namespace contracts = auth::services::contracts;
namespace domain = auth::domain::models;
namespace errors = auth::services::errors;
namespace policies = auth::services::policies;
namespace ports = auth::services::ports;

class FakeTransaction final : public ports::DbTransaction {
 public:
  void Commit() override { committed = true; }

  bool committed{false};
};

class FakeTransactionManager final : public ports::TransactionManager {
 public:
  std::unique_ptr<ports::DbTransaction> Begin(std::string_view) override {
    ++begin_count;
    return std::make_unique<FakeTransaction>();
  }

  int begin_count{0};
};

class FakePasswordHasher final : public ports::PasswordHasher {
 public:
  [[nodiscard]] std::string Hash(std::string_view password) const override {
    return "hash:" + std::string{password};
  }

  [[nodiscard]] bool Verify(std::string_view password,
                            std::string_view hash) const override {
    return hash == Hash(password);
  }
};

class FakeJwtTokenProvider final : public ports::security::JwtTokenProvider {
 public:
  [[nodiscard]] contracts::AuthTokens GenerateTokens(
      std::string_view, std::string_view session_id,
      std::string_view) const override {
    return {
        .access_token = "access:" + std::string{session_id},
        .refresh_token = "refresh:" + std::string{session_id},
    };
  }

  [[nodiscard]] std::string GenerateAccessToken(
      std::string_view, std::string_view session_id) const override {
    return "access:" + std::string{session_id};
  }

  [[nodiscard]] std::string GenerateRefreshToken(
      std::string_view, std::string_view session_id,
      std::string_view) const override {
    return "refresh:" + std::string{session_id};
  }

  [[nodiscard]] ports::security::RefreshTokenClaims ParseRefreshToken(
      std::string_view refresh_token) const override {
    return refresh_claims.at(std::string{refresh_token});
  }

  [[nodiscard]] ports::security::AccessTokenClaims ParseAccessToken(
      std::string_view access_token) const override {
    return access_claims.at(std::string{access_token});
  }

  std::unordered_map<std::string, ports::security::RefreshTokenClaims>
      refresh_claims;
  std::unordered_map<std::string, ports::security::AccessTokenClaims>
      access_claims;
};

class FakeIdGenerator final : public ports::support::IdGenerator {
 public:
  [[nodiscard]] std::string Generate() override {
    if (ids.empty()) {
      throw std::logic_error("no fake ids left");
    }

    auto id = ids.front();
    ids.pop_front();
    return id;
  }

  std::deque<std::string> ids;
};

domain::Session MakeSession(
    std::string id,
    std::string user_id,
    std::string token_family_id,
    std::string refresh_token_hash,
    bool revoked = false
) {
  const auto now = std::chrono::system_clock::now();

  domain::Session session;
  session.id = std::move(id);
  session.user_id = std::move(user_id);
  session.device_id = "device-id";
  session.refresh_token_hash = std::move(refresh_token_hash);
  session.ip = "127.0.0.1";
  session.user_agent = "unit-test";
  session.created_at = now;
  session.last_used_at = now;
  session.expires_at = now + std::chrono::hours{24};
  session.revoked_at = revoked ? std::make_optional(now) : std::nullopt;
  session.token_family_id = std::move(token_family_id);
  session.is_active = !revoked;
  return session;
}

domain::User MakeUser(std::string id, std::string password_hash) {
  const auto now = std::chrono::system_clock::now();

  domain::User user;
  user.id = std::move(id);
  user.username = "unit_user";
  user.password = std::move(password_hash);
  user.email = "unit@example.com";
  user.is_email_verified = true;
  user.created_at = now;
  user.password_updated_at = now;
  return user;
}

ports::EmailVerification MakeEmailVerification(
    std::string id,
    std::string user_id,
    std::string code_hash,
    std::int32_t attempts = 0
) {
  ports::EmailVerification verification;
  verification.id = std::move(id);
  verification.user_id = std::move(user_id);
  verification.code_hash = std::move(code_hash);
  verification.expires_at = std::chrono::system_clock::now() + std::chrono::minutes{15};
  verification.attempts = attempts;
  return verification;
}

class FakeSessionRepository final : public ports::SessionRepository {
 public:
  domain::Session Insert(
      ports::DbTransaction&,
      const ports::NewSessionData& data
  ) override {
    domain::Session session;
    session.id = data.id;
    session.user_id = data.user_id;
    session.device_id = data.device_id;
    session.refresh_token_hash = data.refresh_token_hash;
    session.ip = data.ip;
    session.user_agent = data.user_agent;
    session.created_at = std::chrono::system_clock::now();
    session.last_used_at = session.created_at;
    session.expires_at = data.expires_at;
    session.revoked_at = std::nullopt;
    session.token_family_id = data.token_family_id;
    session.replaced_by_session_id = data.replaced_by_session_id;
    session.is_active = true;

    sessions[session.id] = session;
    return session;
  }

  std::optional<domain::Session> FindById(
      std::string_view session_id,
      ports::ReadConsistency consistency
  ) override {
    last_find_by_id_consistency = consistency;
    const auto& source = SessionsFor(consistency);
    const auto it = source.find(std::string{session_id});
    if (it == source.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  std::vector<domain::Session> ListActiveByUserId(
      std::string_view user_id,
      ports::ReadConsistency consistency
  ) override {
    last_list_consistency = consistency;
    const auto& source = SessionsFor(consistency);
    std::vector<domain::Session> result;
    for (const auto& [_, session] : source) {
      if (session.user_id == user_id && !session.revoked_at) {
        result.push_back(session);
      }
    }
    return result;
  }

  void Revoke(ports::DbTransaction&, std::string_view session_id) override {
    sessions.at(std::string{session_id}).revoked_at =
        std::chrono::system_clock::now();
  }

  bool RevokeByUserId(
      ports::DbTransaction&,
      std::string_view session_id,
      std::string_view user_id
  ) override {
    auto& session = sessions.at(std::string{session_id});
    if (session.user_id != user_id || session.revoked_at) {
      return false;
    }
    session.revoked_at = std::chrono::system_clock::now();
    return true;
  }

  void RevokeAllByUserId(
      ports::DbTransaction&,
      std::string_view user_id
  ) override {
    for (auto& [_, session] : sessions) {
      if (session.user_id == user_id && !session.revoked_at) {
        session.revoked_at = std::chrono::system_clock::now();
        session.is_active = false;
      }
    }
  }

  bool RevokeAndReplace(
      ports::DbTransaction&,
      std::string_view session_id,
      std::string_view replacement_session_id
  ) override {
    auto& session = sessions.at(std::string{session_id});
    if (session.revoked_at) {
      return false;
    }

    session.revoked_at = std::chrono::system_clock::now();
    session.replaced_by_session_id = std::string{replacement_session_id};
    session.is_active = false;
    return true;
  }

  void RevokeByTokenFamily(
      ports::DbTransaction&,
      std::string_view user_id,
      std::string_view token_family_id
  ) override {
    for (auto& [_, session] : sessions) {
      if (session.user_id == user_id &&
          session.token_family_id == token_family_id && !session.revoked_at) {
        session.revoked_at = std::chrono::system_clock::now();
        session.is_active = false;
      }
    }
  }

  void UpdateLastUsed(
      ports::DbTransaction&,
      std::string_view session_id,
      std::chrono::system_clock::time_point last_used_at
  ) override {
    ++update_last_used_count;
    sessions.at(std::string{session_id}).last_used_at = last_used_at;
  }

  std::map<std::string, domain::Session> sessions;
  std::map<std::string, domain::Session> replica_sessions;
  std::size_t update_last_used_count{0};
  ports::ReadConsistency last_find_by_id_consistency{
      ports::ReadConsistency::kEventual};
  ports::ReadConsistency last_list_consistency{
      ports::ReadConsistency::kEventual};

 private:
  [[nodiscard]] const std::map<std::string, domain::Session>& SessionsFor(
      ports::ReadConsistency consistency
  ) const {
    if (consistency == ports::ReadConsistency::kEventual &&
        !replica_sessions.empty()) {
      return replica_sessions;
    }
    return sessions;
  }
};

class FakeUserRepository final : public ports::UserRepository {
 public:
  [[nodiscard]] bool ExistsByUsername(std::string_view) override { return false; }
  [[nodiscard]] bool ExistsByEmail(std::string_view) override { return false; }
  [[nodiscard]] bool ExistsByPhone(std::string_view) override { return false; }
  [[nodiscard]] std::optional<domain::User> FindById(
      std::string_view id,
      ports::ReadConsistency consistency
  ) override {
    last_find_consistency = consistency;
    const auto& source = UsersFor(consistency);
    const auto it = source.find(std::string{id});
    if (it != source.end()) {
      return it->second;
    }
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByUsername(
      std::string_view username,
      ports::ReadConsistency consistency
  ) override {
    last_find_consistency = consistency;
    for (const auto& [_, user] : UsersFor(consistency)) {
      if (user.username == username) {
        return user;
      }
    }
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByEmail(
      std::string_view email,
      ports::ReadConsistency consistency
  ) override {
    last_find_consistency = consistency;
    for (const auto& [_, user] : UsersFor(consistency)) {
      if (user.email == email) {
        return user;
      }
    }
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByPhone(
      std::string_view phone,
      ports::ReadConsistency consistency
  ) override {
    last_find_consistency = consistency;
    for (const auto& [_, user] : UsersFor(consistency)) {
      if (user.phone == phone) {
        return user;
      }
    }
    return std::nullopt;
  }
  [[nodiscard]] domain::User Insert(
      ports::DbTransaction&,
      const ports::NewUserData&
  ) override {
    throw std::logic_error("unused");
  }
  [[nodiscard]] domain::User Insert(const ports::NewUserData&) override {
    throw std::logic_error("unused");
  }
  void SetEmailVerified(ports::DbTransaction&, std::string_view, bool) override {}
  void SetEmailVerified(std::string_view, bool) override {}
  void SetPhoneVerified(ports::DbTransaction&, std::string_view, bool) override {}
  void SetPhoneVerified(std::string_view, bool) override {}
  void SoftDelete(ports::DbTransaction&, std::string_view) override {}
  void SoftDelete(std::string_view) override {}
  void UpdatePasswordHash(
      ports::DbTransaction&,
      std::string_view user_id,
      std::string_view new_password_hash
  ) override {
    users.at(std::string{user_id}).password = std::string{new_password_hash};
  }
  void UpdatePasswordHash(std::string_view user_id, std::string_view new_password_hash) override {
    users.at(std::string{user_id}).password = std::string{new_password_hash};
  }

  std::map<std::string, domain::User> users;
  std::map<std::string, domain::User> replica_users;
  ports::ReadConsistency last_find_consistency{
      ports::ReadConsistency::kEventual};

 private:
  [[nodiscard]] const std::map<std::string, domain::User>& UsersFor(
      ports::ReadConsistency consistency
  ) const {
    if (consistency == ports::ReadConsistency::kEventual &&
        !replica_users.empty()) {
      return replica_users;
    }
    return users;
  }
};

class UnusedEmailOutboxRepository final : public ports::EmailOutboxRepository {
 public:
  void Insert(ports::DbTransaction&, const ports::EnqueueVerificationEmail&) override {}
  void Insert(const ports::EnqueueVerificationEmail&) override {}
  std::vector<ports::EmailOutboxEntry> ClaimBatch(
      ports::DbTransaction&,
      std::size_t,
      std::chrono::system_clock::time_point,
      std::chrono::seconds,
      std::size_t
  ) override {
    return {};
  }
  void MarkSent(
      ports::DbTransaction&,
      std::string_view,
      std::chrono::system_clock::time_point,
      std::string_view
  ) override {}
  void Reschedule(
      ports::DbTransaction&,
      std::string_view,
      std::chrono::system_clock::time_point,
      std::string_view
  ) override {}
  void MarkDead(
      ports::DbTransaction&,
      std::string_view,
      std::chrono::system_clock::time_point,
      std::string_view
  ) override {}
};

class FakeEmailVerificationRepository final
    : public ports::EmailVerificationRepository {
 public:
  ports::EmailVerification Insert(
      ports::DbTransaction&,
      const ports::NewEmailVerificationData&
  ) override {
    throw std::logic_error("unused");
  }
  std::optional<ports::EmailVerification> FindActiveByUserId(
      std::string_view user_id,
      std::chrono::system_clock::time_point,
      std::size_t max_attempts
  ) override {
    last_find_max_attempts = max_attempts;
    if (!active || active->user_id != user_id ||
        active->attempts >= static_cast<std::int32_t>(max_attempts) ||
        active->used_at.has_value()) {
      return std::nullopt;
    }
    return active;
  }
  void MarkUsed(
      ports::DbTransaction&,
      std::string_view verification_id,
      std::chrono::system_clock::time_point used_at
  ) override {
    ++mark_used_count;
    if (active && active->id == verification_id) {
      active->used_at = used_at;
    }
  }
  void IncrementAttempts(
      ports::DbTransaction&,
      std::string_view verification_id,
      std::chrono::system_clock::time_point,
      std::size_t max_attempts
  ) override {
    ++increment_attempts_count;
    last_increment_max_attempts = max_attempts;
    if (active && active->id == verification_id &&
        active->attempts < static_cast<std::int32_t>(max_attempts)) {
      ++active->attempts;
    }
  }
  ports::EmailVerificationAttemptCounters CountRecentAttempts(
      std::string_view,
      const std::optional<std::string>&,
      const std::optional<std::string>&,
      std::chrono::system_clock::time_point
  ) override {
    return counters;
  }
  void RecordAttempt(
      ports::DbTransaction&,
      std::string_view email,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      const std::optional<std::string>& user_agent,
      std::chrono::system_clock::time_point
  ) override {
    ++record_attempt_count;
    last_attempt_email = std::string{email};
    last_attempt_user_id = user_id;
    last_attempt_ip = ip;
    last_attempt_user_agent = user_agent;
  }

  std::optional<ports::EmailVerification> active;
  ports::EmailVerificationAttemptCounters counters;
  std::size_t last_find_max_attempts{0};
  std::size_t last_increment_max_attempts{0};
  std::size_t record_attempt_count{0};
  std::size_t increment_attempts_count{0};
  std::size_t mark_used_count{0};
  std::string last_attempt_email;
  std::optional<std::string> last_attempt_user_id;
  std::optional<std::string> last_attempt_ip;
  std::optional<std::string> last_attempt_user_agent;
};

class FakeDeviceRepository final : public ports::DeviceRepository {
 public:
  domain::Device Insert(
      ports::DbTransaction&,
      const ports::NewDeviceData& data
  ) override {
    domain::Device device;
    device.id = "device-id";
    device.user_id = data.user_id;
    device.device_type = data.device_type;
    device.device_name = data.device_name;
    device.os_version = data.os_version;
    device.app_version = data.app_version;
    device.fingerprint = data.fingerprint;
    device.created_at = std::chrono::system_clock::now();
    device.last_seen_at = device.created_at;
    return device;
  }

  std::optional<domain::Device> FindById(std::string_view) override {
    return std::nullopt;
  }
};

class UnusedVerificationCodeGenerator final
    : public ports::VerificationCodeGenerator {
 public:
  std::string Generate() override { return "123456"; }
};

struct AuthServiceFixture final {
  FakeTransactionManager tx_manager;
  FakeUserRepository user_repo;
  UnusedEmailOutboxRepository email_outbox_repo;
  FakeEmailVerificationRepository email_verification_repo;
  FakePasswordHasher password_hasher;
  UnusedVerificationCodeGenerator code_generator;
  FakeJwtTokenProvider token_provider;
  FakeDeviceRepository device_repo;
  FakeSessionRepository session_repo;
  FakeIdGenerator id_generator;
  policies::SessionPolicy session_policy{
      .refresh_token_ttl = std::chrono::seconds{7200}
  };
  auth::services::usecases::AuthService service{
      tx_manager,
      user_repo,
      email_outbox_repo,
      email_verification_repo,
      password_hasher,
      code_generator,
      token_provider,
      device_repo,
      session_repo,
      id_generator,
      session_policy,
      policies::SignInPolicy{},
      policies::EmailVerificationPolicy{},
  };
};

UTEST(AuthServiceVerifyEmail, InvalidCodeConsumesFinalAttemptAndLocksCode) {
  AuthServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);
  fixture.email_verification_repo.active = MakeEmailVerification(
      "verification-id",
      "user-id",
      "hash:123456",
      4
  );

  EXPECT_THROW(
      fixture.service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "000000",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}
      ),
      errors::InvalidCode
  );

  ASSERT_TRUE(fixture.email_verification_repo.active.has_value());
  EXPECT_EQ(fixture.email_verification_repo.active->attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.last_find_max_attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.last_increment_max_attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.record_attempt_count, 1);

  EXPECT_THROW(
      fixture.service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "123456",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}
      ),
      errors::CodeExpired
  );
  EXPECT_EQ(fixture.email_verification_repo.mark_used_count, 0);
}

UTEST(AuthServiceVerifyEmail, RateLimitStopsAttemptBeforeCodeCheck) {
  AuthServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);
  fixture.email_verification_repo.active = MakeEmailVerification(
      "verification-id",
      "user-id",
      "hash:123456"
  );
  fixture.email_verification_repo.counters.email = 5;

  EXPECT_THROW(
      fixture.service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "000000",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}
      ),
      errors::TooManyVerificationAttempts
  );

  EXPECT_EQ(fixture.email_verification_repo.record_attempt_count, 0);
  EXPECT_EQ(fixture.email_verification_repo.increment_attempts_count, 0);
  EXPECT_EQ(fixture.email_verification_repo.mark_used_count, 0);
}

UTEST(AuthServiceConsistency, SignInUsesStrongUserReadAfterPasswordChange) {
  AuthServiceFixture fixture;

  auto primary_user = MakeUser("user-id", "hash:NewStrongPass123!");
  primary_user.username = "unit_user";
  fixture.user_repo.users.emplace("user-id", primary_user);

  auto stale_user = primary_user;
  stale_user.password = "hash:OldStrongPass123!";
  fixture.user_repo.replica_users.emplace("user-id", stale_user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  EXPECT_THROW(
      static_cast<void>(fixture.service.SignIn(
          contracts::SignInCommand{
              .username = "unit_user",
              .password = "OldStrongPass123!",
          }
      )),
      errors::InvalidCredentials
  );
  EXPECT_EQ(fixture.user_repo.last_find_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(AuthServiceSignIn, UsesSessionPolicyForSessionExpiryAndCookieMaxAge) {
  AuthServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  fixture.user_repo.users.emplace("user-id", user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  const auto before = std::chrono::system_clock::now();
  const auto result = fixture.service.SignIn(
      contracts::SignInCommand{
          .username = "unit_user",
          .password = "CurrentPass123!",
      }
  );
  const auto after = std::chrono::system_clock::now();

  EXPECT_EQ(result.session_id, "session-id");
  EXPECT_EQ(result.refresh_token_max_age,
            fixture.session_policy.refresh_token_ttl);

  const auto& session = fixture.session_repo.sessions.at("session-id");
  EXPECT_GE(session.expires_at,
            before + fixture.session_policy.refresh_token_ttl);
  EXPECT_LE(session.expires_at,
            after + fixture.session_policy.refresh_token_ttl);
}

UTEST(AuthServiceSignIn, AllowsUnverifiedEmailWhenPolicyDisabled) {
  AuthServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  const auto result = fixture.service.SignIn(
      contracts::SignInCommand{
          .username = "unit_user",
          .password = "CurrentPass123!",
      }
  );

  EXPECT_EQ(result.session_id, "session-id");
  EXPECT_TRUE(fixture.session_repo.sessions.contains("session-id"));
}

UTEST(AuthServiceSignIn, RejectsUnverifiedEmailWhenPolicyEnabled) {
  AuthServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);

  auth::services::usecases::AuthService service{
      fixture.tx_manager,
      fixture.user_repo,
      fixture.email_outbox_repo,
      fixture.email_verification_repo,
      fixture.password_hasher,
      fixture.code_generator,
      fixture.token_provider,
      fixture.device_repo,
      fixture.session_repo,
      fixture.id_generator,
      fixture.session_policy,
      policies::SignInPolicy{.require_verified_email = true},
      policies::EmailVerificationPolicy{},
  };

  EXPECT_THROW(
      static_cast<void>(service.SignIn(
          contracts::SignInCommand{
              .username = "unit_user",
              .password = "CurrentPass123!",
          }
      )),
      errors::EmailNotVerified
  );
  EXPECT_TRUE(fixture.session_repo.sessions.empty());
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
}

UTEST(AuthServiceConsistency, ChangePasswordUsesStrongUserRead) {
  AuthServiceFixture fixture;

  auto primary_user = MakeUser("user-id", "hash:NewStrongPass123!");
  fixture.user_repo.users.emplace("user-id", primary_user);

  auto stale_user = primary_user;
  stale_user.password = "hash:OldStrongPass123!";
  fixture.user_repo.replica_users.emplace("user-id", stale_user);

  fixture.session_repo.sessions.emplace(
      "current-session-id",
      MakeSession(
          "current-session-id",
          "user-id",
          "family-id",
          "hash:refresh-current-session-id"
      )
  );

  EXPECT_THROW(
      fixture.service.ChangePassword(
          contracts::AuthContext{
              .user_id = "user-id",
              .session_id = "current-session-id",
          },
          contracts::ChangePasswordCommand{
              .current_password = "OldStrongPass123!",
              .new_password = "AnotherStrongPass123!",
          }
      ),
      errors::InvalidCurrentPassword
  );
  EXPECT_EQ(fixture.user_repo.last_find_consistency,
            ports::ReadConsistency::kStrong);
  EXPECT_EQ(fixture.user_repo.users.at("user-id").password,
            "hash:NewStrongPass123!");
  EXPECT_FALSE(
      fixture.session_repo.sessions.at("current-session-id").revoked_at.has_value()
  );
}

UTEST(AuthServiceConsistency, AccessTokenUsesStrongSessionReadAfterLogout) {
  AuthServiceFixture fixture;
  fixture.user_repo.users.emplace(
      "user-id",
      MakeUser("user-id", "hash:CurrentPass123!")
  );

  const auto active_session = MakeSession(
      "current-session-id",
      "user-id",
      "family-id",
      "hash:refresh-current-session-id"
  );
  fixture.session_repo.sessions.emplace("current-session-id", active_session);
  fixture.session_repo.replica_sessions.emplace(
      "current-session-id",
      active_session
  );
  fixture.token_provider.access_claims.emplace(
      "access-current",
      ports::security::AccessTokenClaims{
          .user_id = "user-id",
          .session_id = "current-session-id",
      }
  );

  fixture.service.RevokeCurrentSession(
      contracts::AuthContext{
          .user_id = "user-id",
          .session_id = "current-session-id",
      }
  );

  ASSERT_TRUE(
      fixture.session_repo.sessions.at("current-session-id").revoked_at.has_value()
  );
  ASSERT_FALSE(
      fixture.session_repo.replica_sessions.at("current-session-id")
          .revoked_at.has_value()
  );

  EXPECT_THROW(
      static_cast<void>(fixture.service.AuthenticateAccessToken("access-current")),
      errors::AuthSessionRevoked
  );
  EXPECT_EQ(fixture.session_repo.last_find_by_id_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(AuthServiceSessionActivity, UpdatesLastUsedWhenActivityIsStale) {
  AuthServiceFixture fixture;
  fixture.user_repo.users.emplace(
      "user-id",
      MakeUser("user-id", "hash:CurrentPass123!")
  );

  auto session = MakeSession(
      "current-session-id",
      "user-id",
      "family-id",
      "hash:refresh-current-session-id"
  );
  const auto stale_last_used =
      std::chrono::system_clock::now() - std::chrono::minutes{10};
  session.last_used_at = stale_last_used;
  fixture.session_repo.sessions.emplace("current-session-id", session);
  fixture.token_provider.access_claims.emplace(
      "access-current",
      ports::security::AccessTokenClaims{
          .user_id = "user-id",
          .session_id = "current-session-id",
      }
  );

  const auto before = std::chrono::system_clock::now();
  const auto context =
      fixture.service.AuthenticateAccessToken("access-current");
  const auto after = std::chrono::system_clock::now();

  EXPECT_EQ(context.user_id, "user-id");
  EXPECT_EQ(context.session_id, "current-session-id");
  EXPECT_EQ(fixture.session_repo.update_last_used_count, 1);
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);

  const auto updated_last_used =
      fixture.session_repo.sessions.at("current-session-id").last_used_at;
  ASSERT_TRUE(updated_last_used.has_value());
  EXPECT_GE(*updated_last_used, before);
  EXPECT_LE(*updated_last_used, after);
  EXPECT_GT(*updated_last_used, stale_last_used);
}

UTEST(AuthServiceSessionActivity, SkipsLastUsedUpdateWhenActivityIsFresh) {
  AuthServiceFixture fixture;
  fixture.user_repo.users.emplace(
      "user-id",
      MakeUser("user-id", "hash:CurrentPass123!")
  );

  auto session = MakeSession(
      "current-session-id",
      "user-id",
      "family-id",
      "hash:refresh-current-session-id"
  );
  const auto fresh_last_used = std::chrono::system_clock::now();
  session.last_used_at = fresh_last_used;
  fixture.session_repo.sessions.emplace("current-session-id", session);
  fixture.token_provider.access_claims.emplace(
      "access-current",
      ports::security::AccessTokenClaims{
          .user_id = "user-id",
          .session_id = "current-session-id",
      }
  );

  const auto context =
      fixture.service.AuthenticateAccessToken("access-current");

  EXPECT_EQ(context.user_id, "user-id");
  EXPECT_EQ(context.session_id, "current-session-id");
  EXPECT_EQ(fixture.session_repo.update_last_used_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
  EXPECT_EQ(
      fixture.session_repo.sessions.at("current-session-id").last_used_at,
      fresh_last_used
  );
}

UTEST(AuthServiceConsistency, RefreshReuseDetectionUsesStrongSessionRead) {
  AuthServiceFixture fixture;
  fixture.id_generator.ids.push_back("replacement-session-id");
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old",
      ports::security::RefreshTokenClaims{
          .user_id = "user-id",
          .session_id = "old-session-id",
          .token_family_id = "family-id",
      }
  );

  fixture.session_repo.sessions.emplace(
      "old-session-id",
      MakeSession(
          "old-session-id",
          "user-id",
          "family-id",
          "hash:refresh-old",
          true
      )
  );
  fixture.session_repo.sessions.emplace(
      "active-session-id",
      MakeSession(
          "active-session-id",
          "user-id",
          "family-id",
          "hash:refresh-active"
      )
  );
  fixture.session_repo.replica_sessions.emplace(
      "old-session-id",
      MakeSession(
          "old-session-id",
          "user-id",
          "family-id",
          "hash:refresh-old"
      )
  );

  EXPECT_THROW(
      static_cast<void>(fixture.service.Refresh(
          contracts::RefreshCommand{.refresh_token = "refresh-old"}
      )),
      errors::RefreshTokenReuseDetected
  );
  EXPECT_EQ(fixture.session_repo.last_find_by_id_consistency,
            ports::ReadConsistency::kStrong);
  EXPECT_TRUE(
      fixture.session_repo.sessions.at("active-session-id").revoked_at.has_value()
  );
}

UTEST(AuthServiceRefresh, RotatesRefreshTokenIntoReplacementSession) {
  AuthServiceFixture fixture;
  fixture.id_generator.ids.push_back("new-session-id");
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old",
      ports::security::RefreshTokenClaims{
          .user_id = "user-id",
          .session_id = "old-session-id",
          .token_family_id = "family-id",
      }
  );
  fixture.session_repo.sessions.emplace(
      "old-session-id",
      MakeSession(
          "old-session-id",
          "user-id",
          "family-id",
          "hash:refresh-old"
      )
  );

  const auto before = std::chrono::system_clock::now();
  const auto result = fixture.service.Refresh(
      contracts::RefreshCommand{.refresh_token = "refresh-old"},
      contracts::RequestMeta{.ip = "10.0.0.1", .user_agent = "new-agent"}
  );
  const auto after = std::chrono::system_clock::now();

  EXPECT_EQ(result.access_token, "access:new-session-id");
  EXPECT_EQ(result.refresh_token, "refresh:new-session-id");
  EXPECT_EQ(result.session_id, "new-session-id");
  EXPECT_EQ(result.refresh_token_max_age,
            fixture.session_policy.refresh_token_ttl);

  const auto& old_session = fixture.session_repo.sessions.at("old-session-id");
  ASSERT_TRUE(old_session.revoked_at.has_value());
  ASSERT_TRUE(old_session.replaced_by_session_id.has_value());
  EXPECT_EQ(*old_session.replaced_by_session_id, "new-session-id");

  const auto& replacement =
      fixture.session_repo.sessions.at("new-session-id");
  EXPECT_EQ(replacement.user_id, "user-id");
  EXPECT_EQ(replacement.token_family_id, "family-id");
  EXPECT_EQ(replacement.refresh_token_hash, "hash:refresh:new-session-id");
  ASSERT_TRUE(replacement.device_id.has_value());
  EXPECT_EQ(*replacement.device_id, "device-id");
  ASSERT_TRUE(replacement.ip.has_value());
  EXPECT_EQ(*replacement.ip, "10.0.0.1");
  ASSERT_TRUE(replacement.user_agent.has_value());
  EXPECT_EQ(*replacement.user_agent, "new-agent");
  EXPECT_GE(replacement.expires_at,
            before + fixture.session_policy.refresh_token_ttl);
  EXPECT_LE(replacement.expires_at,
            after + fixture.session_policy.refresh_token_ttl);
}

UTEST(AuthServiceRefresh, RevokesTokenFamilyOnRefreshTokenReuse) {
  AuthServiceFixture fixture;
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old",
      ports::security::RefreshTokenClaims{
          .user_id = "user-id",
          .session_id = "old-session-id",
          .token_family_id = "family-id",
      }
  );
  fixture.session_repo.sessions.emplace(
      "old-session-id",
      MakeSession(
          "old-session-id",
          "user-id",
          "family-id",
          "hash:refresh-old",
          true
      )
  );
  fixture.session_repo.sessions.emplace(
      "active-session-id",
      MakeSession(
          "active-session-id",
          "user-id",
          "family-id",
          "hash:refresh:active-session-id"
      )
  );

  EXPECT_THROW(
      static_cast<void>(fixture.service.Refresh(
          contracts::RefreshCommand{.refresh_token = "refresh-old"}
      )),
      errors::RefreshTokenReuseDetected
  );

  EXPECT_TRUE(
      fixture.session_repo.sessions.at("active-session-id").revoked_at.has_value()
  );
}

UTEST(AuthServiceChangePassword, UpdatesPasswordHashAndRevokesAllUserSessions) {
  AuthServiceFixture fixture;
  fixture.user_repo.users.emplace(
      "user-id",
      MakeUser("user-id", "hash:CurrentPass123!")
  );
  fixture.session_repo.sessions.emplace(
      "current-session-id",
      MakeSession(
          "current-session-id",
          "user-id",
          "family-id",
          "hash:refresh-current-session-id"
      )
  );
  fixture.session_repo.sessions.emplace(
      "other-session-id",
      MakeSession(
          "other-session-id",
          "user-id",
          "family-id-2",
          "hash:refresh-other-session-id"
      )
  );
  fixture.session_repo.sessions.emplace(
      "another-user-session-id",
      MakeSession(
          "another-user-session-id",
          "another-user-id",
          "family-id-3",
          "hash:refresh-another-user-session-id"
      )
  );

  fixture.service.ChangePassword(
      contracts::AuthContext{
          .user_id = "user-id",
          .session_id = "current-session-id",
      },
      contracts::ChangePasswordCommand{
          .current_password = "CurrentPass123!",
          .new_password = "NewStrongPass123!",
      }
  );

  EXPECT_EQ(fixture.user_repo.users.at("user-id").password,
            "hash:NewStrongPass123!");
  EXPECT_TRUE(
      fixture.session_repo.sessions.at("current-session-id").revoked_at.has_value()
  );
  EXPECT_TRUE(
      fixture.session_repo.sessions.at("other-session-id").revoked_at.has_value()
  );
  EXPECT_FALSE(
      fixture.session_repo.sessions.at("another-user-session-id").revoked_at.has_value()
  );
}

UTEST(AuthServiceChangePassword, RejectsInvalidCurrentPasswordWithoutRevokingSessions) {
  AuthServiceFixture fixture;
  fixture.user_repo.users.emplace(
      "user-id",
      MakeUser("user-id", "hash:CurrentPass123!")
  );
  fixture.session_repo.sessions.emplace(
      "current-session-id",
      MakeSession(
          "current-session-id",
          "user-id",
          "family-id",
          "hash:refresh-current-session-id"
      )
  );

  EXPECT_THROW(
      fixture.service.ChangePassword(
          contracts::AuthContext{
              .user_id = "user-id",
              .session_id = "current-session-id",
          },
          contracts::ChangePasswordCommand{
              .current_password = "WrongPass123!",
              .new_password = "NewStrongPass123!",
          }
      ),
      errors::InvalidCurrentPassword
  );

  EXPECT_EQ(fixture.user_repo.users.at("user-id").password,
            "hash:CurrentPass123!");
  EXPECT_FALSE(
      fixture.session_repo.sessions.at("current-session-id").revoked_at.has_value()
  );
}

}  // namespace
