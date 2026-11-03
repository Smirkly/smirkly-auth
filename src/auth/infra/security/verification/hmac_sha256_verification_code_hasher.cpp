#include <auth/infra/security/verification/hmac_sha256_verification_code_hasher.hpp>

#include <string_view>
#include <utility>

namespace smirkly::auth::infra::security {
namespace {

constexpr std::string_view kDomain = "email-verification:v1";

}  // namespace

HmacSha256VerificationCodeHasher::HmacSha256VerificationCodeHasher(
    std::string pepper)
    : hmac_(std::move(pepper)) {}

std::string HmacSha256VerificationCodeHasher::Hash(
    std::string_view user_id, std::string_view code) const {
  return hmac_.Hash(BuildScopedValue(user_id, code));
}

bool HmacSha256VerificationCodeHasher::Verify(std::string_view user_id,
                                              std::string_view code,
                                              std::string_view hash) const {
  return hmac_.Verify(BuildScopedValue(user_id, code), hash);
}

std::string HmacSha256VerificationCodeHasher::BuildScopedValue(
    std::string_view user_id, std::string_view code) {
  std::string value;
  value.reserve(kDomain.size() + user_id.size() + code.size() + 2);
  value.append(kDomain);
  value.push_back('\0');
  value.append(user_id);
  value.push_back('\0');
  value.append(code);
  return value;
}

}  // namespace smirkly::auth::infra::security
