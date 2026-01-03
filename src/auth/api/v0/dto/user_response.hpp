#pragma once

#include <optional>
#include <string>

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

namespace smirkly::auth::api::v0::dto {
    struct UserResponse {
        std::string id;
        std::string username;
        std::optional<std::string> phone;
        std::optional<std::string> email;

        bool is_email_verified = false;
        bool is_phone_verified = false;

    public:
        userver::formats::json::Value ToJson() const {
            userver::formats::json::ValueBuilder vb;
            vb["id"] = id;
            vb["username"] = username;
            if (phone) vb["phone"] = *phone;
            if (email) vb["email"] = *email;
            vb["is_email_verified"] = is_email_verified;
            vb["is_phone_verified"] = is_phone_verified;
            return vb.ExtractValue();
        }
    };
}
