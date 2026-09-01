#include <auth/infra/security/token/random_token_generator.hpp>

#include <array>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>

namespace smirkly::auth::infra::security {
namespace {
constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string Base64UrlNoPadding(const std::vector<unsigned char>& bytes) {
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i + 3 <= bytes.size()) {
    const auto value = (static_cast<unsigned int>(bytes[i]) << 16) |
                       (static_cast<unsigned int>(bytes[i + 1]) << 8) |
                       static_cast<unsigned int>(bytes[i + 2]);
    out.push_back(kBase64UrlAlphabet[(value >> 18) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[(value >> 6) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[value & 0x3f]);
    i += 3;
  }

  const auto remaining = bytes.size() - i;
  if (remaining == 1) {
    const auto value = static_cast<unsigned int>(bytes[i]) << 16;
    out.push_back(kBase64UrlAlphabet[(value >> 18) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3f]);
  } else if (remaining == 2) {
    const auto value = (static_cast<unsigned int>(bytes[i]) << 16) |
                       (static_cast<unsigned int>(bytes[i + 1]) << 8);
    out.push_back(kBase64UrlAlphabet[(value >> 18) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3f]);
    out.push_back(kBase64UrlAlphabet[(value >> 6) & 0x3f]);
  }

  return out;
}

}  // namespace

RandomTokenGenerator::RandomTokenGenerator(std::size_t byte_length)
    : byte_length_(byte_length) {
  if (byte_length_ < 16) {
    throw std::runtime_error("random token byte length must be at least 16");
  }
}

std::string RandomTokenGenerator::Generate() {
  std::vector<unsigned char> bytes(byte_length_);
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return Base64UrlNoPadding(bytes);
}

}  // namespace smirkly::auth::infra::security
