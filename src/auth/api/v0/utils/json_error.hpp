#pragma once

#include <string>
#include <string_view>

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

namespace smirkly::auth::api::v0::utils {
    [[nodiscard]] inline userver::formats::json::Value ErrorResponse(
        std::string_view code,
        std::string_view message
    ) {
        userver::formats::json::ValueBuilder builder;
        builder["code"] = std::string{code};
        builder["message"] = std::string{message};
        return builder.ExtractValue();
    }
}
