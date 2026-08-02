#include <auth/services/usecases/session_service.hpp>

#include <auth/services/errors/access_token_errors.hpp>

namespace smirkly::auth::services::usecases {

SessionService::SessionService(ports::TransactionManager& transaction_manager,
                               ports::SessionRepository& session_repo)
    : transaction_manager_(transaction_manager), session_repo_(session_repo) {}

contracts::SessionsResult SessionService::ListSessions(
    const contracts::AuthContext& context) const {
  return {
      .sessions = session_repo_.ListActiveByUserId(
          context.user_id, ports::ReadConsistency::kStrong),
  };
}

void SessionService::RevokeSession(const contracts::AuthContext& context,
                                   std::string_view session_id) {
  const auto target_session =
      session_repo_.FindById(session_id, ports::ReadConsistency::kStrong);
  if (!target_session) {
    throw errors::SessionNotFound("session not found");
  }
  if (target_session->user_id != context.user_id) {
    throw errors::SessionForbidden("session belongs to another user");
  }
  if (target_session->revoked_at) {
    return;
  }

  auto tx = transaction_manager_.Begin("auth.sessions.revoke");
  session_repo_.RevokeByUserId(*tx, session_id, context.user_id);
  tx->Commit();
}

void SessionService::RevokeCurrentSession(
    const contracts::AuthContext& context) {
  RevokeSession(context, context.session_id);
}

void SessionService::RevokeAllSessions(const contracts::AuthContext& context) {
  auto tx = transaction_manager_.Begin("auth.sessions.revoke_all");
  session_repo_.RevokeAllByUserId(*tx, context.user_id);
  tx->Commit();
}

}  // namespace smirkly::auth::services::usecases
