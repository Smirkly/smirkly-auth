#include <auth/infra/db/pg/mappers/email_verification_mapper.hpp>

#include "auth/services/ports/repositories/email_verification_repository.hpp"

namespace smirkly::auth::infra::db::pg::mappers {
    namespace {
        namespace pg = USERVER_NAMESPACE::storages::postgres;

        std::chrono::system_clock::time_point ToSys(pg::TimePointTz tp) {
            return tp.GetUnderlying();
        }

        std::optional<std::chrono::system_clock::time_point> ToSysOpt(const std::optional<pg::TimePointTz> &tp) {
            if (!tp) return std::nullopt;
            return tp->GetUnderlying();
        }
    }

    services::ports::EmailVerification ToDomain(const types::EmailVerificationPg &r) {
        services::ports::EmailVerification v;
        v.id = r.id;
        v.user_id = r.user_id;
        v.code_hash = r.code_hash;
        v.expires_at = ToSys(r.expires_at);
        v.used_at = ToSysOpt(r.used_at);
        v.attempts = r.attempts;
        return v;
    }
}
