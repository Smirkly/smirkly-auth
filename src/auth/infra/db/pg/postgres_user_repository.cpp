#include <auth/infra/db/pg/postgres_user_repository.hpp>

#include <userver/storages/postgres/cluster.hpp>

#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
    PostgresUserRepository::PostgresUserRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    [[nodiscard]] bool PostgresUserRepository::ExistsByUsername(std::string_view username) {
        auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByUsername,
            username
        );
        return res.AsSingleRow<bool>();
    }

    [[nodiscard]] bool PostgresUserRepository::ExistsByEmail(std::string_view email) {
        auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByEmail,
            email
        );
        return res.AsSingleRow<bool>();
    }

    [[nodiscard]] bool PostgresUserRepository::ExistsByPhone(std::string_view phone) {
        auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByPhone,
            phone
        );
        return res.AsSingleRow<bool>();
    }

    [[nodiscard]] std::optional<domain::models::User> PostgresUserRepository::FindById(std::string_view id) {
        return {};
    }

    [[nodiscard]] std::optional<domain::models::User>
    PostgresUserRepository::FindByUsername(std::string_view username) {
        return {};
    }

    [[nodiscard]] std::optional<domain::models::User> PostgresUserRepository::FindByEmail(std::string_view email) {
        return {};
    }

    [[nodiscard]] std::optional<domain::models::User> PostgresUserRepository::FindByPhone(std::string_view phone) {
        return {};
    }

    [[nodiscard]] domain::models::User PostgresUserRepository::Insert(const services::ports::NewUserData &data) {
        return {};
    }

    void PostgresUserRepository::SetEmailVerified(std::string_view user_id, bool verified) {
        return;
    }

    void PostgresUserRepository::SetPhoneVerified(std::string_view user_id, bool verified) {
        return;
    }

    void PostgresUserRepository::SoftDelete(std::string_view user_id) {
        return;
    }

    void PostgresUserRepository::UpdatePasswordHash(std::string_view user_id, std::string_view new_password_hash) {
        return;
    }
}
