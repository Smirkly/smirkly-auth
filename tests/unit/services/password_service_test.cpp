#include <auth/services/errors/change_password_errors.hpp>
#include <auth/services/errors/password_reset_errors.hpp>
#include <auth/services/usecases/password_service.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <userver/utest/utest.hpp>

namespace {
namespace auth = smirkly::auth;
namespace contracts = auth::services::contracts;
namespace domain = auth::domain::models;
namespace errors = auth::services::errors;
namespace policies = auth::services::policies;
namespace ports = auth::services::ports;
namespace usecases = auth::services::usecases;

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

class FakeTransaction final : public ports::DbTransaction {
 public:
  explicit FakeTransaction(std::size_t& commit_count)
      : commit_count_(commit_count) {}

  void Commit() override { ++commit_count_; }

 private:
  std::size_t& commit_count_;
};

class FakeTransactionManager final : public ports::TransactionManager {
 public:
  std::unique_ptr<ports::DbTransaction> Begin(
      std::string_view tx_name) override {
    transaction_names.emplace_back(tx_name);
    return std::make_unique<FakeTransaction>(commit_count);
  }

  std::vector<std::string> transaction_names;
  std::size_t commit_count{0};
};

class MockUserRepository : public ports::UserRepository {
 public:
  MOCK_METHOD(bool, ExistsByUsername, (std::string_view), (override));
  MOCK_METHOD(bool, ExistsByEmail, (std::string_view), (override));
  MOCK_METHOD(bool, ExistsByPhone, (std::string_view), (override));
  MOCK_METHOD((std::optional<domain::User>), FindById,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD((std::optional<domain::User>), FindByUsername,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD((std::optional<domain::User>), FindByEmail,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD((std::optional<domain::User>), FindByPhone,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD(domain::User, Insert,
              (ports::DbTransaction&, const ports::NewUserData&), (override));
  MOCK_METHOD(domain::User, Insert, (const ports::NewUserData&), (override));
  MOCK_METHOD(void, SetEmailVerified,
              (ports::DbTransaction&, std::string_view, bool), (override));
  MOCK_METHOD(void, SetEmailVerified, (std::string_view, bool), (override));
  MOCK_METHOD(void, SetPhoneVerified,
              (ports::DbTransaction&, std::string_view, bool), (override));
  MOCK_METHOD(void, SetPhoneVerified, (std::string_view, bool), (override));
  MOCK_METHOD(void, SoftDelete, (ports::DbTransaction&, std::string_view),
              (override));
  MOCK_METHOD(void, SoftDelete, (std::string_view), (override));
  MOCK_METHOD(void, UpdatePasswordHash,
              (ports::DbTransaction&, std::string_view, std::string_view),
              (override));
  MOCK_METHOD(void, UpdatePasswordHash, (std::string_view, std::string_view),
              (override));
};

class MockSessionRepository : public ports::SessionRepository {
 public:
  MOCK_METHOD(domain::Session, Insert,
              (ports::DbTransaction&, const ports::NewSessionData&),
              (override));
  MOCK_METHOD((std::optional<domain::Session>), FindById,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD((std::vector<domain::Session>), ListActiveByUserId,
              (std::string_view, ports::ReadConsistency), (override));
  MOCK_METHOD(void, Revoke, (ports::DbTransaction&, std::string_view),
              (override));
  MOCK_METHOD(bool, RevokeByUserId,
              (ports::DbTransaction&, std::string_view, std::string_view),
              (override));
  MOCK_METHOD(void, RevokeAllByUserId,
              (ports::DbTransaction&, std::string_view), (override));
  MOCK_METHOD(bool, RevokeAndReplace,
              (ports::DbTransaction&, std::string_view, std::string_view),
              (override));
  MOCK_METHOD(void, RevokeByTokenFamily,
              (ports::DbTransaction&, std::string_view, std::string_view),
              (override));
  MOCK_METHOD(void, UpdateLastUsed,
              (ports::DbTransaction&, std::string_view,
               std::chrono::system_clock::time_point),
              (override));
};

class MockEmailOutboxRepository : public ports::EmailOutboxRepository {
 public:
  MOCK_METHOD(void, Insert, (ports::DbTransaction&, const ports::EnqueueEmail&),
              (override));
  MOCK_METHOD(void, Insert, (const ports::EnqueueEmail&), (override));
  MOCK_METHOD((std::vector<ports::EmailOutboxEntry>), ClaimBatch,
              (ports::DbTransaction&, std::size_t,
               std::chrono::system_clock::time_point, std::chrono::seconds,
               std::size_t),
              (override));
  MOCK_METHOD(bool, MarkSent,
              (ports::DbTransaction&, std::string_view, std::string_view,
               std::chrono::system_clock::time_point, std::string_view),
              (override));
  MOCK_METHOD(bool, Reschedule,
              (ports::DbTransaction&, std::string_view, std::string_view,
               std::chrono::system_clock::time_point, std::string_view),
              (override));
  MOCK_METHOD(bool, MarkDead,
              (ports::DbTransaction&, std::string_view, std::string_view,
               std::chrono::system_clock::time_point, std::string_view),
              (override));
};

class MockPasswordResetRepository : public ports::PasswordResetRepository {
 public:
  MOCK_METHOD(ports::PasswordReset, Insert,
              (ports::DbTransaction&, const ports::NewPasswordResetData&),
              (override));
  MOCK_METHOD((std::optional<ports::PasswordReset>), FindActiveByUserId,
              (std::string_view, std::chrono::system_clock::time_point,
               std::size_t),
              (override));
  MOCK_METHOD(bool, MarkUsed,
              (ports::DbTransaction&, std::string_view,
               std::chrono::system_clock::time_point, std::size_t),
              (override));
  MOCK_METHOD(void, MarkActiveUsedByUserId,
              (ports::DbTransaction&, std::string_view,
               std::chrono::system_clock::time_point),
              (override));
  MOCK_METHOD(void, IncrementAttempts,
              (ports::DbTransaction&, std::string_view,
               std::chrono::system_clock::time_point, std::size_t),
              (override));
  MOCK_METHOD(bool, TryRecordAttempt,
              (ports::DbTransaction&, std::string_view,
               const std::optional<std::string>&,
               const std::optional<std::string>&,
               const std::optional<std::string>&,
               std::chrono::system_clock::time_point,
               std::chrono::system_clock::time_point, std::size_t, std::size_t,
               std::size_t),
              (override));
};

class MockPasswordHasher : public ports::PasswordHasher {
 public:
  MOCK_METHOD(std::string, Hash, (std::string_view), (const, override));
  MOCK_METHOD(bool, Verify, (std::string_view, std::string_view),
              (const, override));
};

class MockTokenHasher : public ports::security::TokenHasher {
 public:
  MOCK_METHOD(std::string, Hash, (std::string_view), (const, override));
  MOCK_METHOD(bool, Verify, (std::string_view, std::string_view),
              (const, override));
};

class MockTokenGenerator : public ports::security::TokenGenerator {
 public:
  MOCK_METHOD(std::string, Generate, (), (override));
};

class StaticRuntimePolicyProvider final
    : public ports::config::AuthRuntimePolicyProvider {
 public:
  explicit StaticRuntimePolicyProvider(policies::AuthRuntimePolicies policies)
      : policies_(policies) {}

  policies::AuthRuntimePolicies Get() const override { return policies_; }

 private:
  policies::AuthRuntimePolicies policies_;
};

domain::User MakeUser(std::string password_hash) {
  domain::User user;
  user.id = "user-id";
  user.username = "unit_user";
  user.email = "unit@example.com";
  user.password = std::move(password_hash);
  user.is_email_verified = true;
  user.created_at = std::chrono::system_clock::now();
  user.password_updated_at = user.created_at;
  return user;
}

ports::PasswordReset MakeReset(std::string token_hash) {
  return ports::PasswordReset{
      .id = "reset-id",
      .user_id = "user-id",
      .token_hash = std::move(token_hash),
      .expires_at = std::chrono::system_clock::now() + std::chrono::minutes{15},
      .used_at = std::nullopt,
      .attempts = 0,
  };
}

struct PasswordServiceFixture final {
  PasswordServiceFixture()
      : password_service(tx_manager, user_repo, password_reset_repo,
                         email_outbox_repo, session_repo, password_hasher,
                         token_hasher, token_generator) {}

  FakeTransactionManager tx_manager;
  NiceMock<MockUserRepository> user_repo;
  NiceMock<MockPasswordResetRepository> password_reset_repo;
  NiceMock<MockEmailOutboxRepository> email_outbox_repo;
  NiceMock<MockSessionRepository> session_repo;
  NiceMock<MockPasswordHasher> password_hasher;
  NiceMock<MockTokenHasher> token_hasher;
  NiceMock<MockTokenGenerator> token_generator;
  usecases::PasswordService password_service;
};

UTEST(PasswordServiceChange, UsesStrongUserRead) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo,
              FindById("user-id", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:NewStrongPass123!")));
  EXPECT_CALL(fixture.password_hasher,
              Verify("OldStrongPass123!", "hash:NewStrongPass123!"))
      .WillOnce(Return(false));
  EXPECT_CALL(fixture.user_repo, UpdatePasswordHash(_, _, _)).Times(0);
  EXPECT_CALL(fixture.session_repo, RevokeAllByUserId(_, _)).Times(0);

  EXPECT_THROW(fixture.password_service.ChangePassword(
                   contracts::AuthContext{.user_id = "user-id",
                                          .session_id = "session-id"},
                   contracts::ChangePasswordCommand{
                       .current_password = "OldStrongPass123!",
                       .new_password = "AnotherStrongPass123!",
                   }),
               errors::InvalidCurrentPassword);
}

UTEST(PasswordServiceChange, UpdatesHashAndRevokesAllSessions) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo,
              FindById("user-id", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:CurrentPass123!")));
  EXPECT_CALL(fixture.password_hasher,
              Verify("CurrentPass123!", "hash:CurrentPass123!"))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_hasher,
              Verify("NewStrongPass123!", "hash:CurrentPass123!"))
      .WillOnce(Return(false));
  EXPECT_CALL(fixture.password_hasher, Hash("NewStrongPass123!"))
      .WillOnce(Return("hash:NewStrongPass123!"));
  EXPECT_CALL(fixture.user_repo,
              UpdatePasswordHash(_, "user-id", "hash:NewStrongPass123!"));
  EXPECT_CALL(fixture.session_repo, RevokeAllByUserId(_, "user-id"));

  fixture.password_service.ChangePassword(
      contracts::AuthContext{.user_id = "user-id", .session_id = "session-id"},
      contracts::ChangePasswordCommand{
          .current_password = "CurrentPass123!",
          .new_password = "NewStrongPass123!",
      });

  EXPECT_EQ(fixture.tx_manager.transaction_names,
            std::vector<std::string>{"auth.change_password"});
  EXPECT_EQ(fixture.tx_manager.commit_count, 1);
}

UTEST(PasswordServiceReset, UnknownEmailIsEnumerationSafe) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo, FindByEmail("missing@example.com",
                                             ports::ReadConsistency::kStrong))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(fixture.password_reset_repo,
              TryRecordAttempt(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_reset_repo, Insert(_, _)).Times(0);
  EXPECT_CALL(fixture.email_outbox_repo, Insert(_, _)).Times(0);

  EXPECT_NO_THROW(fixture.password_service.RequestReset(
      contracts::RequestPasswordResetCommand{.email = "missing@example.com"},
      contracts::RequestMeta{.ip = "198.51.100.20",
                             .user_agent = "unit-test"}));
  EXPECT_EQ(fixture.tx_manager.commit_count, 1);
}

UTEST(PasswordServiceReset, RequestCreatesHashedTokenAndOutboxJob) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo,
              FindByEmail("unit@example.com", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:CurrentPass123!")));
  EXPECT_CALL(fixture.password_reset_repo,
              TryRecordAttempt(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_reset_repo,
              MarkActiveUsedByUserId(_, "user-id", _));
  EXPECT_CALL(fixture.token_generator, Generate())
      .WillOnce(Return("reset-token"));
  EXPECT_CALL(fixture.token_hasher, Hash("reset-token"))
      .WillOnce(Return("token-hash:reset-token"));
  EXPECT_CALL(fixture.password_reset_repo, Insert(_, _))
      .WillOnce(Invoke(
          [](ports::DbTransaction&, const ports::NewPasswordResetData& data) {
            EXPECT_EQ(data.user_id, "user-id");
            EXPECT_EQ(data.token_hash, "token-hash:reset-token");
            return MakeReset(data.token_hash);
          }));
  EXPECT_CALL(fixture.email_outbox_repo, Insert(_, _))
      .WillOnce(
          Invoke([](ports::DbTransaction&, const ports::EnqueueEmail& job) {
            EXPECT_EQ(job.to_email, "unit@example.com");
            EXPECT_EQ(job.template_name, "password_reset");
            EXPECT_EQ(job.payload.at("token"), "reset-token");
            EXPECT_EQ(job.correlation_id, "reset-id");
          }));

  fixture.password_service.RequestReset(
      contracts::RequestPasswordResetCommand{.email = "unit@example.com"},
      contracts::RequestMeta{.ip = "198.51.100.21", .user_agent = "unit-test"});
  EXPECT_EQ(fixture.tx_manager.commit_count, 1);
}

UTEST(PasswordServiceReset, ConfirmUpdatesPasswordAndRevokesSessions) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo,
              FindByEmail("unit@example.com", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:CurrentPass123!")));
  EXPECT_CALL(fixture.password_reset_repo,
              TryRecordAttempt(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_reset_repo, FindActiveByUserId("user-id", _, _))
      .WillOnce(Return(MakeReset("token-hash:reset-token")));
  EXPECT_CALL(fixture.token_hasher,
              Verify("reset-token", "token-hash:reset-token"))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_hasher,
              Verify("NewStrongPass123!", "hash:CurrentPass123!"))
      .WillOnce(Return(false));
  EXPECT_CALL(fixture.password_hasher, Hash("NewStrongPass123!"))
      .WillOnce(Return("hash:NewStrongPass123!"));
  EXPECT_CALL(fixture.password_reset_repo, MarkUsed(_, "reset-id", _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.user_repo,
              UpdatePasswordHash(_, "user-id", "hash:NewStrongPass123!"));
  EXPECT_CALL(fixture.session_repo, RevokeAllByUserId(_, "user-id"));

  fixture.password_service.ConfirmReset(
      contracts::ConfirmPasswordResetCommand{
          .email = "unit@example.com",
          .token = "reset-token",
          .new_password = "NewStrongPass123!",
      },
      contracts::RequestMeta{.ip = "198.51.100.22", .user_agent = "unit-test"});
  EXPECT_EQ(fixture.tx_manager.commit_count, 2);
}

UTEST(PasswordServiceReset, InvalidTokenConsumesAttemptOnly) {
  PasswordServiceFixture fixture;
  EXPECT_CALL(fixture.user_repo,
              FindByEmail("unit@example.com", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:CurrentPass123!")));
  EXPECT_CALL(fixture.password_reset_repo,
              TryRecordAttempt(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(fixture.password_reset_repo, FindActiveByUserId("user-id", _, _))
      .WillOnce(Return(MakeReset("token-hash:reset-token")));
  EXPECT_CALL(fixture.token_hasher,
              Verify("wrong-token", "token-hash:reset-token"))
      .WillOnce(Return(false));
  EXPECT_CALL(fixture.password_reset_repo,
              IncrementAttempts(_, "reset-id", _, _));
  EXPECT_CALL(fixture.user_repo, UpdatePasswordHash(_, _, _)).Times(0);

  EXPECT_THROW(fixture.password_service.ConfirmReset(
                   contracts::ConfirmPasswordResetCommand{
                       .email = "unit@example.com",
                       .token = "wrong-token",
                       .new_password = "NewStrongPass123!",
                   }),
               errors::InvalidPasswordResetToken);
  EXPECT_EQ(fixture.tx_manager.commit_count, 2);
}

UTEST(PasswordServiceReset, RuntimeRateLimitStopsBeforeTokenCheck) {
  PasswordServiceFixture fixture;
  auto runtime_policies = policies::AuthRuntimePolicies{};
  runtime_policies.password_reset.max_attempts_per_email = 7;
  runtime_policies.password_reset.max_attempts_per_user = 8;
  runtime_policies.password_reset.max_attempts_per_ip = 9;
  StaticRuntimePolicyProvider provider{runtime_policies};
  usecases::PasswordService service{
      fixture.tx_manager,
      fixture.user_repo,
      fixture.password_reset_repo,
      fixture.email_outbox_repo,
      fixture.session_repo,
      fixture.password_hasher,
      fixture.token_hasher,
      fixture.token_generator,
      {},
      {},
      &provider,
  };

  EXPECT_CALL(fixture.user_repo,
              FindByEmail("unit@example.com", ports::ReadConsistency::kStrong))
      .WillOnce(Return(MakeUser("hash:CurrentPass123!")));
  EXPECT_CALL(fixture.password_reset_repo,
              TryRecordAttempt(_, _, _, _, _, _, _, 7, 8, 9))
      .WillOnce(Return(false));
  EXPECT_CALL(fixture.password_reset_repo, FindActiveByUserId(_, _, _))
      .Times(0);
  EXPECT_CALL(fixture.token_hasher, Verify(_, _)).Times(0);

  EXPECT_THROW(service.ConfirmReset(contracts::ConfirmPasswordResetCommand{
                   .email = "unit@example.com",
                   .token = "reset-token",
                   .new_password = "NewStrongPass123!",
               }),
               errors::TooManyPasswordResetAttempts);
  EXPECT_EQ(fixture.tx_manager.commit_count, 0);
}

}  // namespace
