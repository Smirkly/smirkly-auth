#include <auth/infra/security/verification/hmac_sha256_verification_code_hasher.hpp>

#include <stdexcept>

#include <userver/utest/utest.hpp>

namespace {
using smirkly::auth::infra::security::HmacSha256VerificationCodeHasher;

UTEST(HmacSha256VerificationCodeHasher, HashesUserScopedCode) {
  const HmacSha256VerificationCodeHasher hasher{"unit-verification-pepper"};

  EXPECT_EQ(hasher.Hash("user-id", "123456"),
            "hmac-sha256:v1:"
            "5073675b60fd86b04b2acd80dae7308e3c1898c88da442d97df2a3ea9037d019");
}

UTEST(HmacSha256VerificationCodeHasher, VerifiesOnlyMatchingUserCodeAndPepper) {
  const HmacSha256VerificationCodeHasher hasher{"unit-verification-pepper"};
  const auto hash = hasher.Hash("user-id", "123456");

  EXPECT_TRUE(hasher.Verify("user-id", "123456", hash));
  EXPECT_FALSE(hasher.Verify("other-user", "123456", hash));
  EXPECT_FALSE(hasher.Verify("user-id", "654321", hash));
  EXPECT_FALSE(HmacSha256VerificationCodeHasher{"other-pepper"}.Verify(
      "user-id", "123456", hash));
  EXPECT_FALSE(hasher.Verify("user-id", "123456", "malformed-hash"));
}

UTEST(HmacSha256VerificationCodeHasher, SameCodeDiffersBetweenUsers) {
  const HmacSha256VerificationCodeHasher hasher{"unit-verification-pepper"};

  EXPECT_NE(hasher.Hash("first-user", "123456"),
            hasher.Hash("second-user", "123456"));
}

UTEST(HmacSha256VerificationCodeHasher, RejectsEmptyPepper) {
  EXPECT_THROW(static_cast<void>(HmacSha256VerificationCodeHasher{""}),
               std::runtime_error);
}
}  // namespace
