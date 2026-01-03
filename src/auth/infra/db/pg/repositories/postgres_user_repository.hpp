#pragma once

#include <memory>
#include <string_view>

#include <auth/services/ports/repositories/user_repository.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PostgresUserRepository : public services::ports::UserRepository {
    public:
        explicit PostgresUserRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        [[nodiscard]] bool ExistsByUsername(std::string_view username) override;

        [[nodiscard]] bool ExistsByEmail(std::string_view email) override;

        [[nodiscard]] bool ExistsByPhone(std::string_view phone) override;

        [[nodiscard]] std::optional<domain::models::User> FindById(std::string_view id) override;

        [[nodiscard]] std::optional<domain::models::User> FindByUsername(std::string_view username) override;

        [[nodiscard]] std::optional<domain::models::User> FindByEmail(std::string_view email) override;

        [[nodiscard]] std::optional<domain::models::User> FindByPhone(std::string_view phone) override;

        [[nodiscard]] domain::models::User Insert(const services::ports::NewUserData &data) override;

        void SetEmailVerified(std::string_view user_id, bool verified) override;

        void SetPhoneVerified(std::string_view user_id, bool verified) override;

        void SoftDelete(std::string_view user_id) override;

        void UpdatePasswordHash(std::string_view user_id, std::string_view new_password_hash) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
