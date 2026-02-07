#include <auth/infra/security/password/bcrypt_password_hasher.hpp>

#include <bcrypt/BCrypt.hpp>

namespace smirkly::auth::infra::security {
    std::string BcryptPasswordHasher::Hash(std::string_view password) const {
        return BCrypt::generateHash(std::string{password});
    }

    bool BcryptPasswordHasher::Verify(std::string_view password,
                                      std::string_view hash) const {
        return BCrypt::validatePassword(std::string{password}, std::string{hash});
    }
}
