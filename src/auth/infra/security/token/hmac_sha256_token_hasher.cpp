#include <auth/infra/security/token/hmac_sha256_token_hasher.hpp>

#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace smirkly::auth::infra::security {
namespace hmac_sha256_token_hasher {
constexpr std::string_view kHashPrefix = "hmac-sha256:v1:";
constexpr char kHex[] = "0123456789abcdef";

std::string ToHex(const unsigned char* data, unsigned int size) {
  std::string result;
  result.resize(static_cast<std::size_t>(size) * 2);

  for (unsigned int i = 0; i < size; ++i) {
    result[static_cast<std::size_t>(i) * 2] = kHex[data[i] >> 4];
    result[static_cast<std::size_t>(i) * 2 + 1] = kHex[data[i] & 0x0f];
  }

  return result;
}

bool HasPrefix(std::string_view value, std::string_view prefix) noexcept {
  return value.size() >= prefix.size() &&
         value.substr(0, prefix.size()) == prefix;
}
}  // namespace hmac_sha256_token_hasher

HmacSha256TokenHasher::HmacSha256TokenHasher(std::string pepper)
    : pepper_(std::move(pepper)) {
  if (pepper_.empty()) {
    throw std::runtime_error("refresh token pepper must not be empty");
  }
  if (pepper_.size() >
      static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("refresh token pepper is too large");
  }
}

std::string HmacSha256TokenHasher::Hash(std::string_view token) const {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size = 0;

  const auto* result =
      HMAC(EVP_sha256(), pepper_.data(), static_cast<int>(pepper_.size()),
           reinterpret_cast<const unsigned char*>(token.data()), token.size(),
           digest.data(), &digest_size);
  if (result == nullptr) {
    throw std::runtime_error("failed to calculate refresh token HMAC");
  }

  return std::string{hmac_sha256_token_hasher::kHashPrefix} +
         hmac_sha256_token_hasher::ToHex(digest.data(), digest_size);
}

bool HmacSha256TokenHasher::Verify(std::string_view token,
                                   std::string_view hash) const {
  if (!hmac_sha256_token_hasher::HasPrefix(
          hash, hmac_sha256_token_hasher::kHashPrefix)) {
    return false;
  }

  const auto expected = Hash(token);
  if (expected.size() != hash.size()) {
    return false;
  }

  return CRYPTO_memcmp(expected.data(), hash.data(), expected.size()) == 0;
}
}  // namespace smirkly::auth::infra::security
