#include <auth/services/factories/user_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
    ports::NewUserData UserFactory::CreateFromSignUp(
        std::string username,
        std::string password_hash,
        std::optional<std::string> email,
        std::optional<std::string> phone
    ) {
        return ports::NewUserData{
            .username = std::move(username),
            .password_hash = std::move(password_hash),
            .email = std::move(email),
            .phone = std::move(phone)
        };
    }
}
