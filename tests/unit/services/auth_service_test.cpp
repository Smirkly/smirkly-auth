#include <auth/services/errors/refresh_errors.hpp>
#include <auth/services/usecases/auth_service.hpp>

#include <chrono>
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
      std::string_view) const override {
    throw std::logic_error("unused");
  }

  std::unordered_map<std::string, ports::security::RefreshTokenClaims>
      refresh_claims;
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
      std::string_view session_id
  ) override {
    const auto it = sessions.find(std::string{session_id});
    if (it == sessions.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  std::vector<domain::Session> ListActiveByUserId(
      std::string_view user_id
  ) override {
    std::vector<domain::Session> result;
    for (const auto& [_, session] : sessions) {
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
    sessions.at(std::string{session_id}).last_used_at = last_used_at;
  }

  std::map<std::string, domain::Session> sessions;
};

class UnusedUserRepository final : public ports::UserRepository {
 public:
  [[nodiscard]] bool ExistsByUsername(std::string_view) override { return false; }
  [[nodiscard]] bool ExistsByEmail(std::string_view) override { return false; }
  [[nodiscard]] bool ExistsByPhone(std::string_view) override { return false; }
  [[nodiscard]] std::optional<domain::User> FindById(std::string_view) override {
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByUsername(
      std::string_view
  ) override {
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByEmail(
      std::string_view
  ) override {
    return std::nullopt;
  }
  [[nodiscard]] std::optional<domain::User> FindByPhone(
      std::string_view
  ) override {
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
      std::string_view,
      std::string_view
  ) override {}
  void UpdatePasswordHash(std::string_view, std::string_view) override {}
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

class UnusedEmailVerificationRepository final
    : public ports::EmailVerificationRepository {
 public:
  ports::EmailVerification Insert(
      ports::DbTransaction&,
      const ports::NewEmailVerificationData&
  ) override {
    throw std::logic_error("unused");
  }
  std::optional<ports::EmailVerification> FindActiveByUserId(
      std::string_view,
      std::chrono::system_clock::time_point
  ) override {
    return std::nullopt;
  }
  void MarkUsed(
      ports::DbTransaction&,
      std::string_view,
      std::chrono::system_clock::time_point
  ) override {}
  void IncrementAttempts(
      ports::DbTransaction&,
      std::string_view,
      std::chrono::system_clock::time_point
  ) override {}
};

class UnusedDeviceRepository final : public ports::DeviceRepository {
 public:
  domain::Device Insert(
      ports::DbTransaction&,
      const ports::NewDeviceData&
  ) override {
    throw std::logic_error("unused");
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
  UnusedUserRepository user_repo;
  UnusedEmailOutboxRepository email_outbox_repo;
  UnusedEmailVerificationRepository email_verification_repo;
  FakePasswordHasher password_hasher;
  UnusedVerificationCodeGenerator code_generator;
  FakeJwtTokenProvider token_provider;
  UnusedDeviceRepository device_repo;
  FakeSessionRepository session_repo;
  FakeIdGenerator id_generator;
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
  };
};

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

  const auto result = fixture.service.Refresh(
      contracts::RefreshCommand{.refresh_token = "refresh-old"},
      contracts::RequestMeta{.ip = "10.0.0.1", .user_agent = "new-agent"}
  );

  EXPECT_EQ(result.access_token, "access:new-session-id");
  EXPECT_EQ(result.refresh_token, "refresh:new-session-id");
  EXPECT_EQ(result.session_id, "new-session-id");

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

}  // namespace
