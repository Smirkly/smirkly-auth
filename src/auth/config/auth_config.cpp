#include <auth/config/auth_config.hpp>

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

}  // namespace

AuthSecuritySettings ParseAuthSecuritySettings(
    const userver::components::ComponentConfig& cfg) {
  const auto& jwt = cfg["jwt"];

  AuthSecuritySettings settings;
  settings.verification_code_length =
      ParseSize(cfg, "verification_code_length", 6);
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
