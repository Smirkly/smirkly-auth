#pragma once

#include <auth/domain/models/session.hpp>
#include <auth/infra/db/pg/types/session_pg.hpp>

namespace smirkly::auth::infra::db::pg::mappers {
    domain::models::Session ToDomain(const types::SessionPg &r);
}
