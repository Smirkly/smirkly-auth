#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <jwt/jwt.hpp>
#include <userver/formats/json.hpp>

#include <auth/services/errors/refresh_errors.hpp>

namespace smirkly::auth::infra::security::jwt {
namespace {
constexpr std::string_view kAccessTokenType = "access";
constexpr std::string_view kRefreshTokenType = "refresh";
constexpr std::string_view kIssuerClaim = "iss";
constexpr std::string_view kAudienceClaim = "aud";
constexpr std::string_view kSubjectClaim = "sub";
constexpr std::string_view kSessionIdClaim = "sid";
constexpr std::string_view kTokenTypeClaim = "type";
constexpr std::string_view kTokenFamilyClaim = "fam";
constexpr std::string_view kKeyIdHeader = "kid";
constexpr std::string_view kAlgorithm = "RS256";

std::chrono::system_clock::time_point Now() {
  return std::chrono::system_clock::now();
}

std::string Base64UrlEncode(const std::vector<unsigned char>& bytes) {
  if (bytes.empty()) {
    return {};
  }

  const auto encoded_size = 4 * ((bytes.size() + 2) / 3);
  std::string encoded(encoded_size, '\0');

  const auto written =
      EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
                      bytes.data(), static_cast<int>(bytes.size()));
  if (written < 0) {
    throw std::runtime_error("failed to base64-encode RSA public key");
  }

  encoded.resize(static_cast<std::size_t>(written));
  for (char& c : encoded) {
    if (c == '+') {
      c = '-';
    } else if (c == '/') {
      c = '_';
    }
  }

  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }

  return encoded;
}

std::vector<unsigned char> ToBytes(const BIGNUM& bn) {
  const auto size = BN_num_bytes(&bn);
  if (size <= 0) {
    throw std::runtime_error("invalid RSA public key integer");
  }

  std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
  BN_bn2bin(&bn, bytes.data());
  return bytes;
}

struct RsaPublicNumbers final {
  std::string modulus;
  std::string exponent;
};

RsaPublicNumbers ExtractRsaPublicNumbers(const std::string& public_key_pem) {
  using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

  BioPtr bio(BIO_new_mem_buf(public_key_pem.data(),
                             static_cast<int>(public_key_pem.size())),
             BIO_free);
  if (!bio) {
    throw std::runtime_error("failed to allocate BIO for JWT public key");
  }

  PkeyPtr pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
               EVP_PKEY_free);
  if (!pkey) {
    throw std::runtime_error("JWT public key must be an RSA PEM public key");
  }

  BIGNUM* raw_n = nullptr;
  BIGNUM* raw_e = nullptr;
  if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, &raw_n) != 1 ||
      EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &raw_e) != 1) {
    if (raw_n) BN_free(raw_n);
    if (raw_e) BN_free(raw_e);
    throw std::runtime_error(
        "failed to read RSA public numbers from JWT public key");
  }

  BnPtr n(raw_n, BN_free);
  BnPtr e(raw_e, BN_free);

  return {.modulus = Base64UrlEncode(ToBytes(*n)),
          .exponent = Base64UrlEncode(ToBytes(*e))};
}

std::string BuildPublicJwksJson(const JwtConfig& config) {
  const auto numbers = ExtractRsaPublicNumbers(config.public_key_pem);

  userver::formats::json::ValueBuilder key;
  key["kty"] = "RSA";
  key["use"] = "sig";
  key["kid"] = config.key_id;
  key["alg"] = std::string{kAlgorithm};
  key["n"] = numbers.modulus;
  key["e"] = numbers.exponent;

  userver::formats::json::ValueBuilder keys(
      userver::formats::json::Type::kArray);
  keys.PushBack(key.ExtractValue());

  userver::formats::json::ValueBuilder jwks;
  jwks["keys"] = keys.ExtractValue();
  return userver::formats::json::ToString(jwks.ExtractValue());
}

void ValidateConfig(const JwtConfig& config) {
  if (config.private_key_pem.empty()) {
    throw std::runtime_error(
        "jwt.private-key-path points to an empty private key");
  }
  if (config.public_key_pem.empty()) {
    throw std::runtime_error(
        "jwt.public-key-path points to an empty public key");
  }
  if (config.key_id.empty()) {
    throw std::runtime_error("jwt.key-id must not be empty");
  }
  if (config.issuer.empty()) {
    throw std::runtime_error("jwt.issuer must not be empty");
  }
  if (config.audience.empty()) {
    throw std::runtime_error("jwt.audience must not be empty");
  }
  if (config.access_ttl <= std::chrono::seconds{0}) {
    throw std::runtime_error("jwt.access-token-ttl-seconds must be positive");
  }
  if (config.refresh_ttl <= std::chrono::seconds{0}) {
    throw std::runtime_error("jwt.refresh-token-ttl-seconds must be positive");
  }
}
}  // namespace

JwtCppTokenProvider::JwtCppTokenProvider(JwtConfig config)
    : config_(std::move(config)) {
  ValidateConfig(config_);
  public_jwks_json_ = BuildPublicJwksJson(config_);
}

services::contracts::AuthTokens JwtCppTokenProvider::GenerateTokens(
    std::string_view user_id, std::string_view session_id,
    std::string_view token_family_id) const {
  return {
      .access_token = GenerateAccessToken(user_id, session_id),
      .refresh_token =
          GenerateRefreshToken(user_id, session_id, token_family_id),
  };
}

std::string JwtCppTokenProvider::GenerateAccessToken(
    std::string_view user_id, std::string_view session_id) const {
  return GenerateToken(user_id, session_id, std::nullopt, kAccessTokenType,
                       config_.access_ttl);
}

std::string JwtCppTokenProvider::GenerateRefreshToken(
    std::string_view user_id, std::string_view session_id,
    std::string_view token_family_id) const {
  return GenerateToken(user_id, session_id, std::string(token_family_id),
                       kRefreshTokenType, config_.refresh_ttl);
}

services::ports::security::RefreshTokenClaims
JwtCppTokenProvider::ParseRefreshToken(std::string_view refresh_token) const {
  try {
    auto decoded = ::jwt::decode(
        std::string(refresh_token), ::jwt::params::algorithms({kAlgorithm}),
        ::jwt::params::secret(config_.public_key_pem),
        ::jwt::params::verify(true), ::jwt::params::issuer(config_.issuer),
        ::jwt::params::aud(config_.audience));

    const auto header_json = decoded.header().create_json_obj();
    const auto key_id =
        header_json.at(std::string{kKeyIdHeader}).get<std::string>();
    if (key_id != config_.key_id) {
      throw services::errors::InvalidRefreshToken("invalid refresh token");
    }

    const auto issuer = decoded.payload().get_claim_value<std::string>(
        std::string{kIssuerClaim});
    if (issuer != config_.issuer) {
      throw services::errors::InvalidRefreshToken("invalid refresh token");
    }

    const auto audience = decoded.payload().get_claim_value<std::string>(
        std::string{kAudienceClaim});
    if (audience != config_.audience) {
      throw services::errors::InvalidRefreshToken("invalid refresh token");
    }

    const auto token_type = decoded.payload().get_claim_value<std::string>(
        std::string{kTokenTypeClaim});
    if (token_type != kRefreshTokenType) {
      throw services::errors::InvalidRefreshToken("invalid refresh token");
    }

    services::ports::security::RefreshTokenClaims claims{
        .user_id = decoded.payload().get_claim_value<std::string>(
            std::string{kSubjectClaim}),
        .session_id = decoded.payload().get_claim_value<std::string>(
            std::string{kSessionIdClaim}),
        .token_family_id = std::nullopt,
    };

    try {
      claims.token_family_id = decoded.payload().get_claim_value<std::string>(
          std::string{kTokenFamilyClaim});
    } catch (const std::exception&) {
    }

    return claims;
  } catch (const services::errors::InvalidRefreshToken&) {
    throw;
  } catch (const std::exception&) {
    throw services::errors::InvalidRefreshToken("invalid refresh token");
  }
}

const std::string& JwtCppTokenProvider::GetPublicJwksJson() const noexcept {
  return public_jwks_json_;
}

std::string JwtCppTokenProvider::GenerateToken(
    std::string_view user_id, std::string_view session_id,
    const std::optional<std::string>& token_family_id,
    std::string_view token_type, std::chrono::seconds ttl) const {
  const auto now = Now();

  ::jwt::jwt_object obj{::jwt::params::algorithm(std::string{kAlgorithm}),
                        ::jwt::params::secret(config_.private_key_pem),
                        ::jwt::params::payload({
                            {"sub", std::string(user_id)},
                            {"sid", std::string(session_id)},
                            {"type", std::string(token_type)},
                        })};
  obj.header().add_header(std::string{kKeyIdHeader}, config_.key_id);

  if (token_family_id) {
    obj.add_claim("fam", *token_family_id);
  }

  obj.add_claim("iss", config_.issuer)
      .add_claim("aud", config_.audience)
      .add_claim("iat", now)
      .add_claim("exp", now + ttl);

  std::error_code ec;
  auto token = obj.signature(ec);
  if (ec) {
    throw std::runtime_error("failed to sign JWT with RSA key: " +
                             ec.message());
  }

  return token;
}
}  // namespace smirkly::auth::infra::security::jwt
