#include <stdexcept>

#include <auth/infra/db/pg/mappers/device_mapper.hpp>

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

        domain::models::DeviceType DeviceTypeFromPg(std::string_view value) {
            if (value == "ios") return domain::models::DeviceType::kIos;
            if (value == "android") return domain::models::DeviceType::kAndroid;
            if (value == "web") return domain::models::DeviceType::kWeb;
            if (value == "desktop") return domain::models::DeviceType::kDesktop;
            throw std::runtime_error("unknown device_type_enum value");
        }
    }

    domain::models::Device ToDomain(const types::DevicePg &r) {
        domain::models::Device d;
        d.id = r.id;
        d.user_id = r.user_id;
        d.device_type = DeviceTypeFromPg(r.device_type);
        d.device_name = r.device_name;
        d.os_version = r.os_version;
        d.app_version = r.app_version;
        d.fingerprint = r.fingerprint;
        d.created_at = ToSys(r.created_at);
        d.last_seen_at = ToSysOpt(r.last_seen_at);
        return d;
    }

    std::string ToPg(domain::models::DeviceType type) {
        switch (type) {
            case domain::models::DeviceType::kIos:
                return "ios";
            case domain::models::DeviceType::kAndroid:
                return "android";
            case domain::models::DeviceType::kWeb:
                return "web";
            case domain::models::DeviceType::kDesktop:
                return "desktop";
        }

        throw std::runtime_error("unsupported DeviceType");
    }
}
