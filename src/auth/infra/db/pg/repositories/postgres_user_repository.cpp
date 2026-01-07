#include <auth/infra/db/pg/repositories/postgres_user_repository.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/io/row_types.hpp>

#include <smirkly::auth/sql_queries.hpp>

#include "auth/infra/db/pg/transactions/pg_transaction.hpp"

namespace smirkly::auth::infra::db::pg {
    PostgresUserRepository::PostgresUserRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    bool PostgresUserRepository::ExistsByUsername(std::string_view username) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByUsername,
            username
        );
        return res.AsSingleRow<bool>();
    }

    bool PostgresUserRepository::ExistsByEmail(std::string_view email) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByEmail,
            email
        );
        return res.AsSingleRow<bool>();
    }

    bool PostgresUserRepository::ExistsByPhone(std::string_view phone) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersExistsByPhone,
            phone
        );
        return res.AsSingleRow<bool>();
    }

    std::optional<domain::models::User> PostgresUserRepository::FindById(std::string_view id) {
        return {};
    }

    std::optional<domain::models::User>
    PostgresUserRepository::FindByUsername(std::string_view username) {
        return {};
    }

    std::optional<domain::models::User> PostgresUserRepository::FindByEmail(std::string_view email) {
        return {};
    }

    std::optional<domain::models::User> PostgresUserRepository::FindByPhone(std::string_view phone) {
        return {};
    }


    domain::models::User PostgresUserRepository::Insert(services::ports::DbTransaction &tx,
                                                        const services::ports::NewUserData &data) {
        return {};
    }

    domain::models::User PostgresUserRepository::Insert(const services::ports::NewUserData &data) {
        try {
            const auto res = pg_cluster_->Execute(
                USERVER_NAMESPACE::storages::postgres::ClusterHostType::kMaster,
                sql::kUsersInsert,
                data.username,
                data.email,
                data.phone,
                data.password_hash
            );

            using Row = std::tuple<
                std::string,
                std::string,
                std::optional<std::string>,
                std::optional<std::string>,
                std::string,
                bool,
                bool>;

            const auto row = res.AsSingleRow<Row>(USERVER_NAMESPACE::storages::postgres::kRowTag);

            domain::models::User user;
            user.id = std::get<0>(row);
            user.username = std::get<1>(row);
            user.email = std::get<2>(row);
            user.phone = std::get<3>(row);
            user.password = std::get<4>(row);
            user.is_email_verified = std::get<5>(row);
            user.is_phone_verified = std::get<6>(row);

            return user;
        } catch (const USERVER_NAMESPACE::storages::postgres::UniqueViolation &e) {
            throw;
        }
    }


    void PostgresUserRepository::SetEmailVerified(services::ports::DbTransaction &tx, std::string_view user_id,
                                                  bool verified) {
    }

    void PostgresUserRepository::SetEmailVerified(std::string_view user_id, bool verified) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresUserRepository::SetEmailVerified.AutoTx"
        );

        PostgresUserRepository::SetEmailVerified(tx, user_id, verified);

        tx.Commit();
    }


    void PostgresUserRepository::SetPhoneVerified(services::ports::DbTransaction &tx, std::string_view user_id,
                                                  bool verified) {
    }

    void PostgresUserRepository::SetPhoneVerified(std::string_view user_id, bool verified) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresUserRepository::SetPhoneVerified.AutoTx"
        );

        PostgresUserRepository::SetPhoneVerified(tx, user_id, verified);

        tx.Commit();
    }


    void PostgresUserRepository::SoftDelete(services::ports::DbTransaction &tx, std::string_view user_id) {
    }

    void PostgresUserRepository::SoftDelete(std::string_view user_id) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresUserRepository::SoftDelete.AutoTx"
        );

        PostgresUserRepository::SoftDelete(tx, user_id);

        tx.Commit();
    }


    void PostgresUserRepository::UpdatePasswordHash(services::ports::DbTransaction &tx, std::string_view user_id,
                                                    std::string_view new_password_hash) {
    }

    void PostgresUserRepository::UpdatePasswordHash(std::string_view user_id, std::string_view new_password_hash) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresUserRepository::UpdatePasswordHash.AutoTx"
        );

        PostgresUserRepository::UpdatePasswordHash(tx, user_id, new_password_hash);

        tx.Commit();
    }
}
