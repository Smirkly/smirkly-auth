#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/usecases/session_service.hpp>

#include <userver/utest/utest.hpp>

#include "auth_test_fakes.hpp"

namespace {
namespace auth = smirkly::auth;
namespace contracts = auth::services::contracts;
namespace errors = auth::services::errors;
namespace ports = auth::services::ports;
namespace usecases = auth::services::usecases;

using auth::tests::FakeSessionRepository;
using auth::tests::FakeTransactionManager;
using auth::tests::MakeSession;

struct SessionServiceFixture final {
  FakeTransactionManager tx_manager;
  FakeSessionRepository session_repo;
  usecases::SessionService session_service{tx_manager, session_repo};
};

const contracts::AuthContext kContext{
    .user_id = "user-id",
    .session_id = "current-session-id",
};

UTEST(SessionService, ListsActiveSessionsUsingStrongRead) {
  SessionServiceFixture fixture;
  fixture.session_repo.sessions.emplace(
      "current-session-id", MakeSession("current-session-id", "user-id",
                                        "family-id", "token-hash:current"));
  fixture.session_repo.sessions.emplace(
      "revoked-session-id",
      MakeSession("revoked-session-id", "user-id", "family-id-2",
                  "token-hash:revoked", true));
  fixture.session_repo.sessions.emplace(
      "other-session-id", MakeSession("other-session-id", "other-user-id",
                                      "family-id-3", "token-hash:other"));

  const auto result = fixture.session_service.ListSessions(kContext);

  ASSERT_EQ(result.sessions.size(), 1);
  EXPECT_EQ(result.sessions.front().id, "current-session-id");
  EXPECT_EQ(fixture.session_repo.last_list_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(SessionService, RevokesOwnedSessionTransactionally) {
  SessionServiceFixture fixture;
  fixture.session_repo.sessions.emplace(
      "target-session-id", MakeSession("target-session-id", "user-id",
                                       "family-id", "token-hash:target"));

  fixture.session_service.RevokeSession(kContext, "target-session-id");

  EXPECT_TRUE(fixture.session_repo.sessions.at("target-session-id")
                  .revoked_at.has_value());
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
  EXPECT_EQ(fixture.session_repo.last_find_by_id_consistency,
            ports::ReadConsistency::kStrong);
}

UTEST(SessionService, RejectsSessionOwnedByAnotherUser) {
  SessionServiceFixture fixture;
  fixture.session_repo.sessions.emplace(
      "target-session-id", MakeSession("target-session-id", "other-user-id",
                                       "family-id", "token-hash:target"));

  EXPECT_THROW(
      fixture.session_service.RevokeSession(kContext, "target-session-id"),
      errors::SessionForbidden);
  EXPECT_FALSE(fixture.session_repo.sessions.at("target-session-id")
                   .revoked_at.has_value());
  EXPECT_EQ(fixture.tx_manager.begin_count, 0);
}

UTEST(SessionService, RevokesAllSessionsForCurrentUserOnly) {
  SessionServiceFixture fixture;
  fixture.session_repo.sessions.emplace(
      "current-session-id", MakeSession("current-session-id", "user-id",
                                        "family-id", "token-hash:current"));
  fixture.session_repo.sessions.emplace(
      "other-owned-session-id",
      MakeSession("other-owned-session-id", "user-id", "family-id-2",
                  "token-hash:other-owned"));
  fixture.session_repo.sessions.emplace(
      "foreign-session-id", MakeSession("foreign-session-id", "other-user-id",
                                        "family-id-3", "token-hash:foreign"));

  fixture.session_service.RevokeAllSessions(kContext);

  EXPECT_TRUE(fixture.session_repo.sessions.at("current-session-id")
                  .revoked_at.has_value());
  EXPECT_TRUE(fixture.session_repo.sessions.at("other-owned-session-id")
                  .revoked_at.has_value());
  EXPECT_FALSE(fixture.session_repo.sessions.at("foreign-session-id")
                   .revoked_at.has_value());
  EXPECT_EQ(fixture.tx_manager.begin_count, 1);
}

}  // namespace
