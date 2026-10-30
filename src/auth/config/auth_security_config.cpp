#include <auth/config/auth_security_config.hpp>

#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace smirkly::auth::config {
namespace {

std::string ReadTextFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open JWT key file: " + path);
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::size_t ParseSize(const userver::components::ComponentConfig& cfg,
                      const std::string& key, std::size_t default_value) {
  const auto value =
      cfg[key].As<std::int64_t>(static_cast<std::int64_t>(default_value));
  if (value <= 0) {
    throw std::runtime_error(key + " must be positive");
  }
  if (static_cast<std::uint64_t>(value) >
      static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    throw std::runtime_error(key + " is too large");
  }
  return static_cast<std::size_t>(value);
}

std::uint32_t ParseUint32(const userver::components::ComponentConfig& cfg,
                          const std::string& key, std::uint32_t default_value) {
  const auto value = cfg[key].As<std::int64_t>(default_value);
  if (value <= 0 || static_cast<std::uint64_t>(value) >
                        static_cast<std::uint64_t>(
                            std::numeric_limits<std::uint32_t>::max())) {
    throw std::runtime_error(key + " must be a positive uint32 value");
  }
  return static_cast<std::uint32_t>(value);
}

}  // namespace

AuthSecuritySettings ParseAuthSecuritySettings(
    const userver::components::ComponentConfig& cfg) {
  const auto& jwt = cfg["jwt"];

  AuthSecuritySettings settings;
  const auto& password_hashing = cfg["password-hashing"];
  const auto& argon2id = password_hashing["argon2id"];
  const infra::security::Argon2idParams defaults;
  settings.password_hashing = PasswordHashingSettings{
      .task_processor_name = password_hashing["task-processor"].As<std::string>(
          "password-hashing-task-processor"),
      .argon2id =
          infra::security::Argon2idParams{
              .time_cost =
                  ParseUint32(argon2id, "time-cost", defaults.time_cost),
              .memory_cost_kib = ParseUint32(argon2id, "memory-cost-kib",
                                             defaults.memory_cost_kib),
              .parallelism =
                  ParseUint32(argon2id, "parallelism", defaults.parallelism),
              .salt_length =
                  ParseUint32(argon2id, "salt-length", defaults.salt_length),
              .hash_length =
                  ParseUint32(argon2id, "hash-length", defaults.hash_length),
          },
  };
  if (settings.password_hashing.task_processor_name.empty()) {
    throw std::runtime_error(
        "password-hashing.task-processor must not be empty");
  }
  settings.password_reset_token_bytes =
      ParseSize(cfg, "password_reset_token_bytes", 32);
  settings.refresh_token_pepper = cfg["refresh-token-pepper"].As<std::string>();
  if (settings.refresh_token_pepper.empty()) {
    throw std::runtime_error("refresh-token-pepper must not be empty");
  }
  settings.jwt = JwtSettings{
      .private_key_path = jwt["private-key-path"].As<std::string>(),
      .public_key_path = jwt["public-key-path"].As<std::string>(),
      .key_id = jwt["key-id"].As<std::string>(),
      .issuer = jwt["issuer"].As<std::string>(),
      .audience = jwt["audience"].As<std::string>(),
      .access_ttl =
          std::chrono::seconds{
              jwt["access-token-ttl-seconds"].As<std::int64_t>()},
      .refresh_ttl =
          std::chrono::seconds{
              jwt["refresh-token-ttl-seconds"].As<std::int64_t>()},
  };
  return settings;
}

infra::security::jwt::JwtConfig LoadJwtConfig(const JwtSettings& settings) {
  return infra::security::jwt::JwtConfig{
      .private_key_pem = ReadTextFile(settings.private_key_path),
      .public_key_pem = ReadTextFile(settings.public_key_path),
      .key_id = settings.key_id,
      .issuer = settings.issuer,
      .audience = settings.audience,
      .access_ttl = settings.access_ttl,
      .refresh_ttl = settings.refresh_ttl,
  };
}

}  // namespace smirkly::auth::config
