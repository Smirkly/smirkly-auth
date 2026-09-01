#pragma once

#include <string>
#include <string_view>

#include <userver/formats/json/value.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/server/http/http_status.hpp>

namespace smirkly::auth::api::v0::utils {
[[nodiscard]] inline userver::formats::json::Value ErrorResponse(
    std::string_view code, std::string_view message) {
  userver::formats::json::ValueBuilder builder;
  builder["code"] = std::string{code};
  builder["message"] = std::string{message};
  return builder.ExtractValue();
}

template <typename HttpRequest>
[[nodiscard]] userver::formats::json::Value BadRequestResponse(
    const HttpRequest& request, std::string_view code,
    std::string_view message) {
  request.GetHttpResponse().SetStatus(
      userver::server::http::HttpStatus::kBadRequest);
  return ErrorResponse(code, message);
}
}  // namespace smirkly::auth::api::v0::utils
