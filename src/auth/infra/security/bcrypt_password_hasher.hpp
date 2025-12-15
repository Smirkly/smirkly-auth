#pragma once

#include <auth/services/ports/password_hasher.hpp>

namespace smirkly::auth::infra::security {
    class BcryptPasswordHasher final : public services::ports::PasswordHasher {
    public:
        [[nodiscard]] std::string Hash(std::string_view password) const override;

        [[nodiscard]] bool Verify(std::string_view password,
                                  std::string_view hash) const override;
    };
}
