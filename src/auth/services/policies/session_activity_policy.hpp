#pragma once

#include <chrono>

#include <auth/domain/models/session.hpp>

namespace smirkly::auth::services::policies {
inline bool ShouldUpdateLastUsed(const domain::models::Session& session,
                                 std::chrono::system_clock::time_point now,
                                 std::chrono::seconds threshold) noexcept {
  return !session.last_used_at || *session.last_used_at + threshold <= now;
}
}  // namespace smirkly::auth::services::policies
