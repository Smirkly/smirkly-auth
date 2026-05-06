#pragma once

#include <chrono>
#include <cstddef>
#include <string>

#include <userver/components/component_config.hpp>

#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>

namespace smirkly::auth::config {

struct JwtSettings {
  std::string private_key_path;
  std::string public_key_path;
  std::string key_id;
  std::string issuer;
  std::string audience;
  std::chrono::seconds access_ttl;
  std::chrono::seconds refresh_ttl;
};

struct AuthSecuritySettings {
  JwtSettings jwt;
  std::size_t verification_code_length{6};
};

AuthSecuritySettings ParseAuthSecuritySettings(
    const userver::components::ComponentConfig& cfg);

infra::security::jwt::JwtConfig LoadJwtConfig(const JwtSettings& settings);

}  // namespace smirkly::auth::config
