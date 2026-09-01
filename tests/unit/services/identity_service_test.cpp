#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/usecases/identity_service.hpp>

#include <userver/utest/utest.hpp>

#include "auth_test_fakes.hpp"

namespace {
namespace auth = smirkly::auth;
namespace contracts = auth::services::contracts;
namespace errors = auth::services::errors;
namespace ports = auth::services::ports;
namespace usecases = auth::services::usecases;

using auth::tests::FakeEmailVerificationRepository;
using auth::tests::FakePasswordHasher;
using auth::tests::FakeSignUpAttemptRepository;
using auth::tests::FakeTransactionManager;
using auth::tests::FakeUserRepository;
using auth::tests::MakeEmailVerification;
using auth::tests::MakeUser;
using auth::tests::UnusedEmailOutboxRepository;
using auth::tests::UnusedVerificationCodeGenerator;

struct IdentityServiceFixture final {
  FakeTransactionManager tx_manager;
  FakeUserRepository user_repo;
  UnusedEmailOutboxRepository email_outbox_repo;
  FakeEmailVerificationRepository email_verification_repo;
  FakeSignUpAttemptRepository sign_up_attempt_repo;
  FakePasswordHasher password_hasher;
  UnusedVerificationCodeGenerator code_generator;
  usecases::IdentityService identity_service{
      tx_manager,           user_repo,
      email_outbox_repo,    email_verification_repo,
      sign_up_attempt_repo, password_hasher,
      code_generator,
  };
};

UTEST(IdentityServiceSignUp, RateLimitStopsBeforeUniquenessChecksAndBcrypt) {
  IdentityServiceFixture fixture;
  fixture.sign_up_attempt_repo.allow_attempt = false;

  EXPECT_THROW(static_cast<void>(fixture.identity_service.SignUp(
                   contracts::SignUpCommand{
                       .username = "unit_signup",
                       .password = "StrongPass123!",
                       .phone = std::nullopt,
                       .email = "unit-signup@example.com",
                   },
                   contracts::RequestMeta{
                       .ip = "198.51.100.20",
                       .user_agent = "unit-test",
                   })),
               errors::TooManySignUpAttempts);

  EXPECT_EQ(fixture.sign_up_attempt_repo.try_record_count, 1);
  EXPECT_EQ(fixture.sign_up_attempt_repo.record_attempt_count, 0);
  EXPECT_EQ(fixture.sign_up_attempt_repo.last_ip, "198.51.100.20");
  EXPECT_EQ(fixture.sign_up_attempt_repo.last_max_attempts_per_ip, 20);
  EXPECT_EQ(fixture.password_hasher.hash_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
}

UTEST(IdentityServiceSignUp, ValidationFailureDoesNotConsumeRateLimit) {
  IdentityServiceFixture fixture;

  EXPECT_THROW(static_cast<void>(fixture.identity_service.SignUp(
                   contracts::SignUpCommand{
                       .username = "x",
                       .password = "short",
                       .phone = std::nullopt,
                       .email = "not-an-email",
                   },
                   contracts::RequestMeta{
                       .ip = "198.51.100.21",
                       .user_agent = "unit-test",
                   })),
               errors::SignUpValidation);

  EXPECT_EQ(fixture.sign_up_attempt_repo.try_record_count, 0);
  EXPECT_EQ(fixture.password_hasher.hash_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
}

UTEST(IdentityServiceVerifyEmail, InvalidCodeConsumesFinalAttemptAndLocksCode) {
  IdentityServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);
  fixture.email_verification_repo.active =
      MakeEmailVerification("verification-id", "user-id", "hash:123456", 4);

  EXPECT_THROW(
      fixture.identity_service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "000000",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}),
      errors::InvalidCode);

  ASSERT_TRUE(fixture.email_verification_repo.active.has_value());
  EXPECT_EQ(fixture.email_verification_repo.active->attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.last_find_max_attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.last_increment_max_attempts, 5);
  EXPECT_EQ(fixture.email_verification_repo.record_attempt_count, 1);

  EXPECT_THROW(
      fixture.identity_service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "123456",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}),
      errors::CodeExpired);
  EXPECT_EQ(fixture.email_verification_repo.mark_used_count, 0);
}

UTEST(IdentityServiceVerifyEmail, RateLimitStopsAttemptBeforeCodeCheck) {
  IdentityServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);
  fixture.email_verification_repo.active =
      MakeEmailVerification("verification-id", "user-id", "hash:123456");
  fixture.email_verification_repo.counters.email = 5;

  EXPECT_THROW(
      fixture.identity_service.VerifyEmail(
          contracts::VerifyEmailCommand{
              .email = "unit@example.com",
              .code = "000000",
          },
          contracts::RequestMeta{.ip = "127.0.0.1", .user_agent = "unit-test"}),
      errors::TooManyVerificationAttempts);

  EXPECT_EQ(fixture.email_verification_repo.record_attempt_count, 0);
  EXPECT_EQ(fixture.email_verification_repo.increment_attempts_count, 0);
  EXPECT_EQ(fixture.email_verification_repo.mark_used_count, 0);
}

}  // namespace
