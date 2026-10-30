#include <stdexcept>
#include <string>

#include <userver/utest/utest.hpp>

#include <auth/infra/security/password/argon2id_password_hasher.hpp>

namespace smirkly::auth::infra::security {
namespace {

UTEST(Argon2idPasswordHasher, HashesAndVerifiesPassword) {
  const Argon2idPasswordHasher hasher;
  const std::string password = "super-secret-password";

  const auto hash = hasher.Hash(password);

  EXPECT_TRUE(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
  EXPECT_TRUE(hasher.Verify(password, hash));
}

UTEST(Argon2idPasswordHasher, RejectsWrongPassword) {
  const Argon2idPasswordHasher hasher;
  const auto hash = hasher.Hash("correct-password");

  EXPECT_FALSE(hasher.Verify("wrong-password", hash));
}

UTEST(Argon2idPasswordHasher, GeneratesUniqueSaltForEachHash) {
  const Argon2idPasswordHasher hasher;

  const auto first_hash = hasher.Hash("same-password");
  const auto second_hash = hasher.Hash("same-password");

  EXPECT_NE(first_hash, second_hash);
  EXPECT_TRUE(hasher.Verify("same-password", first_hash));
  EXPECT_TRUE(hasher.Verify("same-password", second_hash));
}

UTEST(Argon2idPasswordHasher, RejectsMalformedEncodedHash) {
  const Argon2idPasswordHasher hasher;

  EXPECT_FALSE(hasher.Verify("password", "not-an-argon2id-hash"));
  EXPECT_FALSE(hasher.Verify("password", ""));
}

UTEST(Argon2idPasswordHasher, SupportsPasswordContainingNullByte) {
  const Argon2idPasswordHasher hasher;
  const std::string password{"before\0after", 12};

  const auto hash = hasher.Hash(password);

  EXPECT_TRUE(hasher.Verify(password, hash));
  EXPECT_FALSE(hasher.Verify("before", hash));
}

UTEST(Argon2idPasswordHasher, RejectsInvalidParameters) {
  EXPECT_THROW(static_cast<void>(Argon2idPasswordHasher{
                   Argon2idParams{.time_cost = 0},
               }),
               std::invalid_argument);
  EXPECT_THROW(static_cast<void>(Argon2idPasswordHasher{
                   Argon2idParams{.parallelism = 0},
               }),
               std::invalid_argument);
}

}  // namespace
}  // namespace smirkly::auth::infra::security
