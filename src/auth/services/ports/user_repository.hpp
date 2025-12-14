#pragma once

#include <optional>

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::domain::services::ports {
    struct NewUserData {
        std::string username;
        std::string password_hash;
        std::optional<std::string> email;
        std::optional<std::string> phone;
    };

    class UserRepository {
    public:
        virtual ~UserRepository() = default;

        [[nodiscard]] virtual bool ExistsByUsername(std::string_view username) = 0;

        [[nodiscard]] virtual bool ExistsByEmail(std::string_view email) = 0;

        [[nodiscard]] virtual bool ExistsByPhone(std::string_view phone) = 0;

        [[nodiscard]] virtual std::optional<models::User> FindById(std::string_view id) = 0;

        [[nodiscard]] virtual std::optional<models::User> FindByUsername(std::string_view username) = 0;

        [[nodiscard]] virtual std::optional<models::User> FindByEmail(std::string_view email) = 0;

        [[nodiscard]] virtual std::optional<models::User> FindByPhone(std::string_view phone) = 0;

        [[nodiscard]] virtual models::User Insert(const NewUserData &data) = 0;

        virtual void set_email_verified(std::string_view user_id, bool verified) = 0;

        virtual void set_phone_verified(std::string_view user_id, bool verified) = 0;

        virtual void soft_delete(std::string_view user_id) = 0;

        virtual void update_password_hash(std::string_view user_id, std::string_view new_password_hash) = 0;
    };
}
