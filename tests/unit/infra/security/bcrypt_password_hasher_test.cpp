#include <userver/utest/utest.hpp>

#include <auth/infra/security/bcrypt_password_hasher.hpp>

namespace {
    using smirkly::auth::infra::security::BcryptPasswordHasher;

    UTEST(BcryptPasswordHasher, HashAndVerify_SamePasswordOk) {
        BcryptPasswordHasher hasher;

        const std::string password = "super-secret-password";
        const auto hash = hasher.Hash(password);

        EXPECT_FALSE(hash.empty());
        EXPECT_TRUE(hasher.Verify(password, hash));
    }

    UTEST(BcryptPasswordHasher, Verify_WrongPasswordFails) {
        BcryptPasswordHasher hasher;

        const std::string password = "correct-password";
        const std::string other = "wrong-password";
        const auto hash = hasher.Hash(password);

        EXPECT_FALSE(hash.empty());
        EXPECT_FALSE(hasher.Verify(other, hash));
    }

    UTEST(BcryptPasswordHasher, Hash_SamePasswordDifferentHashes) {
        BcryptPasswordHasher hasher;

        const std::string password = "same-password";
        const auto hash1 = hasher.Hash(password);
        const auto hash2 = hasher.Hash(password);

        EXPECT_NE(hash1, hash2);
        EXPECT_TRUE(hasher.Verify(password, hash1));
        EXPECT_TRUE(hasher.Verify(password, hash2));
    }
}
