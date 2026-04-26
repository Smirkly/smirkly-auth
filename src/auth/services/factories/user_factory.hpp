#pragma once

#include <optional>
#include <string>

#include <auth/services/ports/repositories/user_repository.hpp>

namespace smirkly::auth::services::factories {
    class UserFactory final {
    public:
        [[nodiscard]] static ports::NewUserData CreateFromSignUp(
            std::string username,
            std::string password_hash,
            std::optional<std::string> email,
            std::optional<std::string> phone
        );
    };
}
