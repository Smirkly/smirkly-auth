#pragma once

#include <optional>
#include <string>

#include <userver/formats/parse/common_containers.hpp>
#include <userver/formats/parse/common.hpp>
#include <userver/formats/json/value.hpp>

namespace smirkly::auth::api::v0::dto {
    struct SignInRequest final {
        std::optional<std::string> username;
        std::optional<std::string> email;
        std::optional<std::string> phone;
        std::string password;
    };

    SignInRequest Parse(const userver::formats::json::Value &value,
                        userver::formats::parse::To<SignInRequest>);
}
