#include <auth/infra/db/pg/mappers/password_reset_mapper.hpp>

namespace smirkly::auth::infra::db::pg::mappers {
namespace {
namespace pg = USERVER_NAMESPACE::storages::postgres;

std::chrono::system_clock::time_point ToSys(pg::TimePointTz value) {
  return value.GetUnderlying();
}

std::optional<std::chrono::system_clock::time_point> ToSysOpt(
    const std::optional<pg::TimePointTz>& value) {
  if (!value) {
    return std::nullopt;
  }
  return value->GetUnderlying();
}

}  // namespace

services::ports::PasswordReset ToDomain(const types::PasswordResetPg& row) {
  return services::ports::PasswordReset{
      .id = row.id,
      .user_id = row.user_id,
      .token_hash = row.token_hash,
      .expires_at = ToSys(row.expires_at),
      .used_at = ToSysOpt(row.used_at),
      .attempts = row.attempts,
  };
}

}  // namespace smirkly::auth::infra::db::pg::mappers
