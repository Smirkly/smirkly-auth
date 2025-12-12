#pragma once

#include <string>
#include <optional>

#include <userver/formats/json/value.hpp>

namespace smirkly::auth::api::v0::dto {
    class SignUpRequest {
    public:
        std::optional<std::string> phone;
        std::optional<std::string> email;
        std::string username;
        std::string password;

    public:
        static SignUpRequest FromJson(const userver::formats::json::Value &body);
    };
}
