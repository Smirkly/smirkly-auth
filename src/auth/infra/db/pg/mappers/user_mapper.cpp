#include <auth/infra/db/pg/mappers/user_mapper.hpp>

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

    domain::models::User ToDomain(const types::UserPg &r) {
        domain::models::User u;
        u.id = r.id;
        u.username = r.username;
        u.email = r.email;
        u.phone = r.phone;
        u.password = r.password_hash;
        u.is_email_verified = r.is_email_verified;
        u.is_phone_verified = r.is_phone_verified;
        u.created_at = ToSys(r.created_at);
        u.password_updated_at = ToSys(r.password_updated_at);
        u.deleted_at = ToSysOpt(r.deleted_at);
        return u;
    }
}
