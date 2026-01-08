#pragma once

#include <auth/domain/models/user.hpp>
#include <auth/infra/db/pg/types/user_pg.hpp>

namespace smirkly::auth::infra::db::pg::mappers {
    domain::models::User ToDomain(const types::UserPg &row);
}
