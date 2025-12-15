#pragma once

#include <string>

namespace smirkly::auth::domain::services::ports {
    class PasswordHasher {
    public:
        virtual ~PasswordHasher() = default;

        [[nodiscard]] virtual std::string Hash(std::string_view password) const = 0;

        [[nodiscard]] virtual bool Verify(std::string_view password,
                                          std::string_view hash) const = 0;
    };
}
