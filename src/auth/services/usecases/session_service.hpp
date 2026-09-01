#pragma once

#include <string_view>

#include <auth/services/contracts/auth_context.hpp>
#include <auth/services/ports/repositories/session_repository.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>

namespace smirkly::auth::services::usecases {

class SessionService final {
 public:
  SessionService(ports::TransactionManager& transaction_manager,
                 ports::SessionRepository& session_repo);

  contracts::SessionsResult ListSessions(
      const contracts::AuthContext& context) const;

  void RevokeSession(const contracts::AuthContext& context,
                     std::string_view session_id);

  void RevokeCurrentSession(const contracts::AuthContext& context);

  void RevokeAllSessions(const contracts::AuthContext& context);

 private:
  ports::TransactionManager& transaction_manager_;
  ports::SessionRepository& session_repo_;
};

}  // namespace smirkly::auth::services::usecases
