#pragma once

#include <chrono>
#include <cstddef>
#include <string>

#include <userver/components/component_config.hpp>

#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>
#include <auth/infra/security/password/argon2id_password_hasher.hpp>

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

struct PasswordHashingSettings {
  std::string task_processor_name{"password-hashing-task-processor"};
  infra::security::Argon2idParams argon2id;
};

struct AuthSecuritySettings {
  JwtSettings jwt;
  PasswordHashingSettings password_hashing;
  std::size_t password_reset_token_bytes{32};
  std::string refresh_token_pepper;
};

AuthSecuritySettings ParseAuthSecuritySettings(
    const userver::components::ComponentConfig& cfg);

infra::security::jwt::JwtConfig LoadJwtConfig(const JwtSettings& settings);

}  // namespace smirkly::auth::config
