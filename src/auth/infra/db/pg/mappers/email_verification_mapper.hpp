#pragma once

#include <auth/infra/db/pg/types/email_verifications_pg.hpp>

#include "auth/services/ports/repositories/email_verification_repository.hpp"

namespace smirkly::auth::infra::db::pg::mappers {
    services::ports::EmailVerification ToDomain(const types::EmailVerificationPg &r);
}
