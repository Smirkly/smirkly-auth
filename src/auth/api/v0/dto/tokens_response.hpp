#pragma once

#include <string>
#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>

namespace smirkly::auth::api::v0::dto {
    struct TokensResponse {
        std::string access_token;
        std::string refresh_token;

        userver::formats::json::Value ToJson() const {
            userver::formats::json::ValueBuilder vb;
            vb["access_token"] = access_token;
            vb["refresh_token"] = refresh_token;
            return vb.ExtractValue();
        }
    };
}
