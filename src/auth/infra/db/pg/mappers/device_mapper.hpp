#pragma once

#include <auth/domain/models/device.hpp>
#include <auth/infra/db/pg/types/device_pg.hpp>

namespace smirkly::auth::infra::db::pg::mappers {
    domain::models::Device ToDomain(const types::DevicePg &r);

    std::string ToPg(domain::models::DeviceType type);
}
