#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/refresh_errors.hpp>
#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/usecases/authentication_service.hpp>
#include <auth/services/usecases/session_service.hpp>

#include <userver/utest/utest.hpp>

#include "auth_test_fakes.hpp"

namespace {
namespace auth = smirkly::auth;
namespace contracts = auth::services::contracts;
namespace errors = auth::services::errors;
namespace policies = auth::services::policies;
namespace ports = auth::services::ports;
namespace usecases = auth::services::usecases;

using auth::tests::FakeDeviceRepository;
using auth::tests::FakeIdGenerator;
using auth::tests::FakeJwtTokenProvider;
using auth::tests::FakePasswordHasher;
using auth::tests::FakeSessionRepository;
using auth::tests::FakeSignInAttemptRepository;
using auth::tests::FakeTokenHasher;
using auth::tests::FakeTransactionManager;
using auth::tests::FakeUserRepository;
using auth::tests::MakeSession;
using auth::tests::MakeUser;

struct AuthenticationServiceFixture final {
  FakeTransactionManager tx_manager;
  FakeUserRepository user_repo;
  FakeSignInAttemptRepository sign_in_attempt_repo;
  FakePasswordHasher password_hasher;
  FakeTokenHasher refresh_token_hasher;
  FakeJwtTokenProvider token_provider;
  FakeDeviceRepository device_repo;
  FakeSessionRepository session_repo;
  FakeIdGenerator id_generator;
  policies::SessionPolicy session_policy{.refresh_token_ttl =
                                             std::chrono::seconds{7200}};
  usecases::AuthenticationService authentication_service{
      tx_manager,           user_repo,
      sign_in_attempt_repo, password_hasher,
      refresh_token_hasher, token_provider,
      device_repo,          session_repo,
      id_generator,         session_policy,
  };
  usecases::SessionService session_service{tx_manager, session_repo};
};

UTEST(AuthenticationServiceConsistency,
      SignInUsesStrongUserReadAfterPasswordChange) {
  AuthenticationServiceFixture fixture;

  auto primary_user = MakeUser("user-id", "hash:NewStrongPass123!");
  primary_user.username = "unit_user";
  fixture.user_repo.users.emplace("user-id", primary_user);

  auto stale_user = primary_user;
  stale_user.password = "hash:OldStrongPass123!";
  fixture.user_repo.replica_users.emplace("user-id", stale_user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                   contracts::SignInCommand{
                       .username = "unit_user",
                       .email = std::nullopt,
                       .phone = std::nullopt,
                       .password = "OldStrongPass123!",
                   })),
               errors::InvalidCredentials);
  EXPECT_EQ(fixture.user_repo.last_find_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(AuthenticationServiceSignIn,
      UsesSessionPolicyForSessionExpiryAndCookieMaxAge) {
  AuthenticationServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  fixture.user_repo.users.emplace("user-id", user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  const auto before = std::chrono::system_clock::now();
  const auto result =
      fixture.authentication_service.SignIn(contracts::SignInCommand{
          .username = "unit_user",
          .email = std::nullopt,
          .phone = std::nullopt,
          .password = "CurrentPass123!",
      });
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

UTEST(AuthenticationServiceSignIn, AllowsUnverifiedEmailWhenPolicyDisabled) {
  AuthenticationServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);

  fixture.id_generator.ids.push_back("session-id");
  fixture.id_generator.ids.push_back("family-id");

  usecases::AuthenticationService service{
      fixture.tx_manager,
      fixture.user_repo,
      fixture.sign_in_attempt_repo,
      fixture.password_hasher,
      fixture.refresh_token_hasher,
      fixture.token_provider,
      fixture.device_repo,
      fixture.session_repo,
      fixture.id_generator,
      fixture.session_policy,
      policies::SignInPolicy{.require_verified_email = false},
  };

  const auto result = service.SignIn(contracts::SignInCommand{
      .username = "unit_user",
      .email = std::nullopt,
      .phone = std::nullopt,
      .password = "CurrentPass123!",
  });

  EXPECT_EQ(result.session_id, "session-id");
  EXPECT_TRUE(fixture.session_repo.sessions.contains("session-id"));
}

UTEST(AuthenticationServiceSignIn,
      RejectsTooLongPasswordBeforeRateLimitAndBcrypt) {
  AuthenticationServiceFixture fixture;

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                   contracts::SignInCommand{
                       .username = "unit_user",
                       .email = std::nullopt,
                       .phone = std::nullopt,
                       .password = std::string(73, 'a'),
                   })),
               errors::SignInValidation);

  EXPECT_EQ(fixture.sign_in_attempt_repo.count_recent_attempts_count, 0);
  EXPECT_EQ(fixture.sign_in_attempt_repo.record_attempt_count, 0);
  EXPECT_EQ(fixture.password_hasher.verify_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
}

UTEST(AuthenticationServiceSignIn, RateLimitStopsAttemptBeforePasswordCheck) {
  const auto expect_limited = [](ports::SignInAttemptCounters counters) {
    AuthenticationServiceFixture fixture;

    auto user = MakeUser("user-id", "hash:CurrentPass123!");
    user.username = "unit_user";
    fixture.user_repo.users.emplace("user-id", user);
    fixture.sign_in_attempt_repo.counters = counters;

    EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                     contracts::SignInCommand{
                         .username = "unit_user",
                         .email = std::nullopt,
                         .phone = std::nullopt,
                         .password = "CurrentPass123!",
                     },
                     contracts::RequestMeta{
                         .ip = "198.51.100.10",
                         .user_agent = "unit-test",
                     })),
                 errors::TooManySignInAttempts);

    EXPECT_EQ(fixture.sign_in_attempt_repo.count_recent_attempts_count, 1);
    EXPECT_EQ(fixture.sign_in_attempt_repo.record_attempt_count, 0);
    EXPECT_EQ(fixture.password_hasher.verify_count, 0);
    EXPECT_EQ(fixture.tx_manager.begin_count, 0);
    EXPECT_EQ(fixture.sign_in_attempt_repo.last_login_identifier,
              "username:unit_user");
    EXPECT_EQ(fixture.sign_in_attempt_repo.last_user_id,
              std::make_optional<std::string>("user-id"));
    EXPECT_EQ(fixture.sign_in_attempt_repo.last_ip,
              std::make_optional<std::string>("198.51.100.10"));
  };

  expect_limited(ports::SignInAttemptCounters{.identifier = 10});
  expect_limited(ports::SignInAttemptCounters{.user = 10});
  expect_limited(ports::SignInAttemptCounters{.ip = 50});
}

UTEST(AuthenticationServiceSignIn, InvalidPasswordRecordsRateLimitAttempt) {
  AuthenticationServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  fixture.user_repo.users.emplace("user-id", user);

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                   contracts::SignInCommand{
                       .username = "unit_user",
                       .email = std::nullopt,
                       .phone = std::nullopt,
                       .password = "WrongPass123!",
                   },
                   contracts::RequestMeta{
                       .ip = "198.51.100.11",
                       .user_agent = "unit-test",
                   })),
               errors::InvalidCredentials);

  EXPECT_EQ(fixture.sign_in_attempt_repo.count_recent_attempts_count, 1);
  EXPECT_EQ(fixture.sign_in_attempt_repo.record_attempt_count, 1);
  EXPECT_EQ(fixture.password_hasher.verify_count, 1);
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_login_identifier,
            "username:unit_user");
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_user_id,
            std::make_optional<std::string>("user-id"));
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_ip,
            std::make_optional<std::string>("198.51.100.11"));
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_user_agent,
            std::make_optional<std::string>("unit-test"));
}

UTEST(AuthenticationServiceSignIn, UnknownUserRecordsIdentifierAndIpAttempt) {
  AuthenticationServiceFixture fixture;

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                   contracts::SignInCommand{
                       .username = std::nullopt,
                       .email = "Missing@Example.COM",
                       .phone = std::nullopt,
                       .password = "WrongPass123!",
                   },
                   contracts::RequestMeta{
                       .ip = "198.51.100.12",
                       .user_agent = "unit-test",
                   })),
               errors::InvalidCredentials);

  EXPECT_EQ(fixture.sign_in_attempt_repo.count_recent_attempts_count, 1);
  EXPECT_EQ(fixture.sign_in_attempt_repo.record_attempt_count, 1);
  EXPECT_EQ(fixture.password_hasher.verify_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_login_identifier,
            "email:missing@example.com");
  EXPECT_FALSE(fixture.sign_in_attempt_repo.last_user_id.has_value());
  EXPECT_EQ(fixture.sign_in_attempt_repo.last_ip,
            std::make_optional<std::string>("198.51.100.12"));
}

UTEST(AuthenticationServiceSignIn, RejectsUnverifiedEmailByDefault) {
  AuthenticationServiceFixture fixture;

  auto user = MakeUser("user-id", "hash:CurrentPass123!");
  user.username = "unit_user";
  user.is_email_verified = false;
  fixture.user_repo.users.emplace("user-id", user);

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.SignIn(
                   contracts::SignInCommand{
                       .username = "unit_user",
                       .email = std::nullopt,
                       .phone = std::nullopt,
                       .password = "CurrentPass123!",
                   })),
               errors::EmailNotVerified);
  EXPECT_TRUE(fixture.session_repo.sessions.empty());
  EXPECT_EQ(fixture.sign_in_attempt_repo.record_attempt_count, 1);
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
}

UTEST(AuthenticationServiceConsistency,
      AccessTokenUsesStrongSessionReadAfterLogout) {
  AuthenticationServiceFixture fixture;
  fixture.user_repo.users.emplace("user-id",
                                  MakeUser("user-id", "hash:CurrentPass123!"));

  const auto active_session =
      MakeSession("current-session-id", "user-id", "family-id",
                  "hash:refresh-current-session-id");
  fixture.session_repo.sessions.emplace("current-session-id", active_session);
  fixture.session_repo.replica_sessions.emplace("current-session-id",
                                                active_session);
  fixture.token_provider.access_claims.emplace(
      "access-current", ports::security::AccessTokenClaims{
                            .user_id = "user-id",
                            .session_id = "current-session-id",
                        });

  fixture.session_service.RevokeCurrentSession(contracts::AuthContext{
      .user_id = "user-id",
      .session_id = "current-session-id",
  });

  ASSERT_TRUE(fixture.session_repo.sessions.at("current-session-id")
                  .revoked_at.has_value());
  ASSERT_FALSE(fixture.session_repo.replica_sessions.at("current-session-id")
                   .revoked_at.has_value());

  EXPECT_THROW(
      static_cast<void>(fixture.authentication_service.AuthenticateAccessToken(
          "access-current")),
      errors::AuthSessionRevoked);
  EXPECT_EQ(fixture.session_repo.last_find_by_id_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(AuthenticationServiceSessionActivity,
      UpdatesLastUsedWhenActivityIsStale) {
  AuthenticationServiceFixture fixture;
  fixture.user_repo.users.emplace("user-id",
                                  MakeUser("user-id", "hash:CurrentPass123!"));

  auto session = MakeSession("current-session-id", "user-id", "family-id",
                             "hash:refresh-current-session-id");
  const auto stale_last_used =
      std::chrono::system_clock::now() - std::chrono::minutes{10};
  session.last_used_at = stale_last_used;
  fixture.session_repo.sessions.emplace("current-session-id", session);
  fixture.token_provider.access_claims.emplace(
      "access-current", ports::security::AccessTokenClaims{
                            .user_id = "user-id",
                            .session_id = "current-session-id",
                        });

  const auto before = std::chrono::system_clock::now();
  const auto context =
      fixture.authentication_service.AuthenticateAccessToken("access-current");
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

UTEST(AuthenticationServiceSessionActivity,
      SkipsLastUsedUpdateWhenActivityIsFresh) {
  AuthenticationServiceFixture fixture;
  fixture.user_repo.users.emplace("user-id",
                                  MakeUser("user-id", "hash:CurrentPass123!"));

  auto session = MakeSession("current-session-id", "user-id", "family-id",
                             "hash:refresh-current-session-id");
  const auto fresh_last_used = std::chrono::system_clock::now();
  session.last_used_at = fresh_last_used;
  fixture.session_repo.sessions.emplace("current-session-id", session);
  fixture.token_provider.access_claims.emplace(
      "access-current", ports::security::AccessTokenClaims{
                            .user_id = "user-id",
                            .session_id = "current-session-id",
                        });

  const auto context =
      fixture.authentication_service.AuthenticateAccessToken("access-current");

  EXPECT_EQ(context.user_id, "user-id");
  EXPECT_EQ(context.session_id, "current-session-id");
  EXPECT_EQ(fixture.session_repo.update_last_used_count, 0);
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
  EXPECT_EQ(fixture.session_repo.sessions.at("current-session-id").last_used_at,
            fresh_last_used);
}

UTEST(AuthenticationServiceConsistency,
      RefreshReuseDetectionUsesStrongSessionRead) {
  AuthenticationServiceFixture fixture;
  fixture.id_generator.ids.push_back("replacement-session-id");
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old", ports::security::RefreshTokenClaims{
                         .user_id = "user-id",
                         .session_id = "old-session-id",
                         .token_family_id = "family-id",
                     });

  fixture.session_repo.sessions.emplace(
      "old-session-id", MakeSession("old-session-id", "user-id", "family-id",
                                    "token-hash:refresh-old", true));
  fixture.session_repo.sessions.emplace(
      "active-session-id",
      MakeSession("active-session-id", "user-id", "family-id",
                  "token-hash:refresh-active"));
  fixture.session_repo.replica_sessions.emplace(
      "old-session-id", MakeSession("old-session-id", "user-id", "family-id",
                                    "token-hash:refresh-old"));

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.Refresh(
                   contracts::RefreshCommand{.refresh_token = "refresh-old"})),
               errors::RefreshTokenReuseDetected);
  EXPECT_EQ(fixture.session_repo.last_find_by_id_consistency,
            ports::ReadConsistency::kStrong);
  EXPECT_EQ(fixture.refresh_token_hasher.verify_count, 1);
  EXPECT_EQ(fixture.password_hasher.verify_count, 0);
  EXPECT_TRUE(fixture.session_repo.sessions.at("active-session-id")
                  .revoked_at.has_value());
}

UTEST(AuthenticationServiceRefresh, RotatesRefreshTokenIntoReplacementSession) {
  AuthenticationServiceFixture fixture;
  fixture.id_generator.ids.push_back("new-session-id");
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old", ports::security::RefreshTokenClaims{
                         .user_id = "user-id",
                         .session_id = "old-session-id",
                         .token_family_id = "family-id",
                     });
  fixture.session_repo.sessions.emplace(
      "old-session-id", MakeSession("old-session-id", "user-id", "family-id",
                                    "token-hash:refresh-old"));

  const auto before = std::chrono::system_clock::now();
  const auto result = fixture.authentication_service.Refresh(
      contracts::RefreshCommand{.refresh_token = "refresh-old"},
      contracts::RequestMeta{.ip = "10.0.0.1", .user_agent = "new-agent"});
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

  const auto& replacement = fixture.session_repo.sessions.at("new-session-id");
  EXPECT_EQ(replacement.user_id, "user-id");
  EXPECT_EQ(replacement.token_family_id, "family-id");
  EXPECT_EQ(replacement.refresh_token_hash,
            "token-hash:refresh:new-session-id");
  EXPECT_EQ(fixture.refresh_token_hasher.verify_count, 1);
  EXPECT_EQ(fixture.refresh_token_hasher.hash_count, 1);
  EXPECT_EQ(fixture.password_hasher.verify_count, 0);
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

UTEST(AuthenticationServiceRefresh, RevokesTokenFamilyOnRefreshTokenReuse) {
  AuthenticationServiceFixture fixture;
  fixture.token_provider.refresh_claims.emplace(
      "refresh-old", ports::security::RefreshTokenClaims{
                         .user_id = "user-id",
                         .session_id = "old-session-id",
                         .token_family_id = "family-id",
                     });
  fixture.session_repo.sessions.emplace(
      "old-session-id", MakeSession("old-session-id", "user-id", "family-id",
                                    "token-hash:refresh-old", true));
  fixture.session_repo.sessions.emplace(
      "active-session-id",
      MakeSession("active-session-id", "user-id", "family-id",
                  "token-hash:refresh:active-session-id"));

  EXPECT_THROW(static_cast<void>(fixture.authentication_service.Refresh(
                   contracts::RefreshCommand{.refresh_token = "refresh-old"})),
               errors::RefreshTokenReuseDetected);

  EXPECT_EQ(fixture.refresh_token_hasher.verify_count, 1);
  EXPECT_EQ(fixture.password_hasher.verify_count, 0);
  EXPECT_TRUE(fixture.session_repo.sessions.at("active-session-id")
                  .revoked_at.has_value());
}

}  // namespace
