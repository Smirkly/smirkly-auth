#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <userver/formats/json/exception.hpp>
#include <userver/formats/json/value.hpp>

namespace smirkly::auth::api::v0::utils {

[[nodiscard]] inline std::optional<std::string> GetString(
    const userver::formats::json::Value& body, std::string_view member) {
  if (!body.HasMember(member)) {
    return std::nullopt;
  }

  try {
    return body[member].As<std::string>();
  } catch (const userver::formats::json::Exception&) {
    return std::nullopt;
  }
}

}  // namespace smirkly::auth::api::v0::utils
