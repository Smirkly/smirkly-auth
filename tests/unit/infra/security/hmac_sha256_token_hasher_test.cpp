#include <auth/infra/security/token/hmac_sha256_token_hasher.hpp>

#include <stdexcept>

#include <userver/utest/utest.hpp>

namespace {
using smirkly::auth::infra::security::HmacSha256TokenHasher;

UTEST(HmacSha256TokenHasher, HashesWithVersionedHmacSha256Format) {
  const HmacSha256TokenHasher hasher{"unit-pepper"};

  EXPECT_EQ(hasher.Hash("refresh-token"),
            "hmac-sha256:v1:"
            "db3c2e154b33a967426037be34f921513e44abe1507a92a2479b3eb1674c0708");
}

UTEST(HmacSha256TokenHasher, VerifiesOnlyMatchingTokenAndPepper) {
  const HmacSha256TokenHasher hasher{"unit-pepper"};
  const auto hash = hasher.Hash("refresh-token");

  EXPECT_TRUE(hasher.Verify("refresh-token", hash));
  EXPECT_FALSE(hasher.Verify("other-token", hash));
  EXPECT_FALSE(
      HmacSha256TokenHasher{"other-pepper"}.Verify("refresh-token", hash));
  EXPECT_FALSE(hasher.Verify("refresh-token", "hash:refresh-token"));
}

UTEST(HmacSha256TokenHasher, RejectsEmptyPepper) {
  EXPECT_THROW(static_cast<void>(HmacSha256TokenHasher{""}),
               std::runtime_error);
}
}  // namespace
