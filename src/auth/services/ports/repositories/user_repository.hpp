#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/domain/models/user.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
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

        [[nodiscard]] virtual std::optional<domain::models::User> FindById(std::string_view id) = 0;

        [[nodiscard]] virtual std::optional<domain::models::User> FindByUsername(std::string_view username) = 0;

        [[nodiscard]] virtual std::optional<domain::models::User> FindByEmail(std::string_view email) = 0;

        [[nodiscard]] virtual std::optional<domain::models::User> FindByPhone(std::string_view phone) = 0;


        [[nodiscard]] virtual domain::models::User Insert(DbTransaction &tx, const NewUserData &data) = 0;

        [[nodiscard]] virtual domain::models::User Insert(const NewUserData &data) = 0;


        virtual void SetEmailVerified(DbTransaction &tx, std::string_view user_id, bool verified) = 0;

        virtual void SetEmailVerified(std::string_view user_id, bool verified) = 0;


        virtual void SetPhoneVerified(DbTransaction &tx, std::string_view user_id, bool verified) = 0;

        virtual void SetPhoneVerified(std::string_view user_id, bool verified) = 0;


        virtual void SoftDelete(DbTransaction &tx, std::string_view user_id) = 0;

        virtual void SoftDelete(std::string_view user_id) = 0;


        virtual void UpdatePasswordHash(DbTransaction &tx, std::string_view user_id,
                                        std::string_view new_password_hash) = 0;

        virtual void UpdatePasswordHash(std::string_view user_id, std::string_view new_password_hash) = 0;
    };
}
