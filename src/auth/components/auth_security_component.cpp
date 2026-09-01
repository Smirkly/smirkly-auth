#include <auth/components/auth_security_component.hpp>

#include <memory>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/config/auth_security_config.hpp>
#include <auth/infra/ids/uuid_generator.hpp>
#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>
#include <auth/infra/security/password/bcrypt_password_hasher.hpp>
#include <auth/infra/security/token/hmac_sha256_token_hasher.hpp>
#include <auth/infra/security/token/random_token_generator.hpp>
#include <auth/infra/security/verification/random_verification_code_generator.hpp>
#include <auth/services/policies/verification_code_policy.hpp>

namespace smirkly::auth::components {

struct AuthSecurityComponent::Impl {
  config::AuthSecuritySettings settings;
  infra::security::jwt::JwtCppTokenProvider token_provider;
  infra::security::BcryptPasswordHasher password_hasher;
  infra::security::HmacSha256TokenHasher refresh_token_hasher;
  infra::security::RandomVerificationCodeGenerator code_generator;
  infra::security::RandomTokenGenerator password_reset_token_generator;
  infra::ids::UuidGenerator uuid_generator;

  explicit Impl(const userver::components::ComponentConfig& cfg)
      : settings(config::ParseAuthSecuritySettings(cfg)),
        token_provider(config::LoadJwtConfig(settings.jwt)),
        password_hasher(),
        refresh_token_hasher(settings.refresh_token_pepper),
        code_generator(services::policies::kVerificationCodeLength),
        password_reset_token_generator(settings.password_reset_token_bytes),
        uuid_generator() {}
};

AuthSecurityComponent::AuthSecurityComponent(
    const userver::components::ComponentConfig& cfg,
    const userver::components::ComponentContext& ctx)
    : userver::components::LoggableComponentBase(cfg, ctx),
      impl_(std::make_unique<Impl>(cfg)) {}

AuthSecurityComponent::~AuthSecurityComponent() = default;

userver::yaml_config::Schema AuthSecurityComponent::GetStaticConfigSchema() {
  using userver::components::LoggableComponentBase;
  using userver::yaml_config::MergeSchemas;

  return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth security providers config
additionalProperties: false
properties:
  refresh-token-pepper:
    type: string
    description: Secret pepper used to HMAC refresh/reset tokens before storing them
  password_reset_token_bytes:
    type: integer
    description: Random byte length for generated password reset tokens
    minimum: 16
    default: 32
  jwt:
    type: object
    description: JWT settings
    additionalProperties: false
    properties:
      issuer:
        type: string
        description: JWT issuer
      audience:
        type: string
        description: JWT audience accepted by Smirkly backend services
      key-id:
        type: string
        description: Public key id written to JWT header and JWKS
      private-key-path:
        type: string
        description: Path to RSA private key PEM used to sign JWTs
      public-key-path:
        type: string
        description: Path to RSA public key PEM exposed through JWKS
      access-token-ttl-seconds:
        type: integer
        description: Access token TTL in seconds
      refresh-token-ttl-seconds:
        type: integer
        description: Refresh token TTL in seconds
)");
}

services::ports::security::JwtTokenProvider&
AuthSecurityComponent::GetJwtTokenProvider() noexcept {
  return impl_->token_provider;
}

const services::ports::security::JwtTokenProvider&
AuthSecurityComponent::GetJwtTokenProvider() const noexcept {
  return impl_->token_provider;
}

services::ports::PasswordHasher&
AuthSecurityComponent::GetPasswordHasher() noexcept {
  return impl_->password_hasher;
}

const services::ports::PasswordHasher&
AuthSecurityComponent::GetPasswordHasher() const noexcept {
  return impl_->password_hasher;
}

services::ports::security::TokenHasher&
AuthSecurityComponent::GetRefreshTokenHasher() noexcept {
  return impl_->refresh_token_hasher;
}

const services::ports::security::TokenHasher&
AuthSecurityComponent::GetRefreshTokenHasher() const noexcept {
  return impl_->refresh_token_hasher;
}

services::ports::security::TokenGenerator&
AuthSecurityComponent::GetPasswordResetTokenGenerator() noexcept {
  return impl_->password_reset_token_generator;
}

const services::ports::security::TokenGenerator&
AuthSecurityComponent::GetPasswordResetTokenGenerator() const noexcept {
  return impl_->password_reset_token_generator;
}

services::ports::VerificationCodeGenerator&
AuthSecurityComponent::GetVerificationCodeGenerator() noexcept {
  return impl_->code_generator;
}

const services::ports::VerificationCodeGenerator&
AuthSecurityComponent::GetVerificationCodeGenerator() const noexcept {
  return impl_->code_generator;
}

services::ports::support::IdGenerator&
AuthSecurityComponent::GetIdGenerator() noexcept {
  return impl_->uuid_generator;
}

const services::ports::support::IdGenerator&
AuthSecurityComponent::GetIdGenerator() const noexcept {
  return impl_->uuid_generator;
}

const std::string& AuthSecurityComponent::GetPublicJwksJson() const noexcept {
  return impl_->token_provider.GetPublicJwksJson();
}

std::chrono::seconds AuthSecurityComponent::GetRefreshTokenTtl()
    const noexcept {
  return impl_->settings.jwt.refresh_ttl;
}

}  // namespace smirkly::auth::components
