#pragma once

#include <string>
#include <optional>

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

namespace smirkly::auth::api::v0::dto {
    struct UserResponse {
        std::string id;
        std::string username;
        std::optional<std::string> phone;
        std::optional<std::string> email;

        userver::formats::json::Value ToJson() const {
            userver::formats::json::ValueBuilder vb;
            vb["id"] = id;
            vb["username"] = username;
            if (phone) vb["phone"] = *phone;
            if (email) vb["email"] = *email;
            return vb.ExtractValue();
        }
    };
}
