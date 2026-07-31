#pragma once

#include <auth/infra/db/pg/types/password_reset_pg.hpp>
#include <auth/services/ports/repositories/password_reset_repository.hpp>

namespace smirkly::auth::infra::db::pg::mappers {

services::ports::PasswordReset ToDomain(const types::PasswordResetPg& row);

}  // namespace smirkly::auth::infra::db::pg::mappers
