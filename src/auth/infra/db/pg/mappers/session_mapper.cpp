#include <auth/infra/db/pg/mappers/session_mapper.hpp>

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

    domain::models::Session ToDomain(const types::SessionPg &r) {
        domain::models::Session s;
        s.id = r.id;
        s.user_id = r.user_id;
        s.device_id = r.device_id;
        s.refresh_token_hash = r.refresh_token_hash;
        s.ip = r.ip;
        s.user_agent = r.user_agent;
        s.created_at = ToSys(r.created_at);
        s.last_used_at = ToSysOpt(r.last_used_at);
        s.expires_at = ToSys(r.expires_at);
        s.revoked_at = ToSysOpt(r.revoked_at);
        s.token_family_id = r.token_family_id;
        s.replaced_by_session_id = r.replaced_by_session_id;
        s.is_active = !s.revoked_at.has_value() && s.expires_at > std::chrono::system_clock::now();
        return s;
    }
}
