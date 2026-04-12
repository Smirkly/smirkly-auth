#include <auth/infra/db/pg/repositories/postgres_user_repository.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/io/row_types.hpp>

#include <auth/infra/db/pg/mappers/user_mapper.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <auth/infra/db/pg/types/user_pg.hpp>
#include <auth/services/errors/sign_up_errors.hpp>
#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    namespace pgsql = USERVER_NAMESPACE::storages::postgres;

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
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersSelectById,
            id
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::UserPg>(pgsql::kRowTag);
        return mappers::ToDomain(row);
    }

    std::optional<domain::models::User>
    PostgresUserRepository::FindByUsername(std::string_view username) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersSelectByUsername,
            username
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::UserPg>(pgsql::kRowTag);
        return mappers::ToDomain(row);
    }

    std::optional<domain::models::User> PostgresUserRepository::FindByEmail(std::string_view email) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersSelectByEmail,
            email
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::UserPg>(pgsql::kRowTag);
        return mappers::ToDomain(row);
    }

    std::optional<domain::models::User> PostgresUserRepository::FindByPhone(std::string_view phone) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kUsersSelectByPhone,
            phone
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::UserPg>(pgsql::kRowTag);
        return mappers::ToDomain(row);
    }


    domain::models::User PostgresUserRepository::Insert(services::ports::DbTransaction &tx,
                                                        const services::ports::NewUserData &data) {
        try {
            auto &pg_tx = AsPgTx(tx, "PostgresUserRepository::Insert");

            const auto res = pg_tx.Native().Execute(
                sql::kUsersInsert,
                data.username,
                data.email,
                data.phone,
                data.password_hash
            );

            const auto row = res.AsSingleRow<types::UserPg>(pgsql::kRowTag);
            return mappers::ToDomain(row);
        } catch (const USERVER_NAMESPACE::storages::postgres::UniqueViolation &e) {
            const auto constraint = e.GetConstraint();
            if (constraint == "users_username_uniq") throw services::errors::UsernameTaken("username taken");
            if (constraint == "users_email_uniq") throw services::errors::EmailTaken("email taken");
            if (constraint == "users_phone_uniq") throw services::errors::PhoneTaken("phone taken");
            throw;
        }
    }

    domain::models::User PostgresUserRepository::Insert(const services::ports::NewUserData &data) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresUserRepository::Insert.AutoTx"
        );

        const auto user = PostgresUserRepository::Insert(tx, data);

        tx.Commit();

        return user;
    }


    void PostgresUserRepository::SetEmailVerified(services::ports::DbTransaction &tx, std::string_view user_id,
                                                  bool verified) {
        auto &pg_tx = AsPgTx(tx, "PostgresUserRepository::SetEmailVerified");

        pg_tx.Native().Execute(
            sql::kUsersSetEmailVerified,
            user_id,
            verified
        );
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
        auto &pg_tx = AsPgTx(tx, "PostgresUserRepository::SetPhoneVerified");

        pg_tx.Native().Execute(
            sql::kUsersSetPhoneVerified,
            user_id,
            verified
        );
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
        auto &pg_tx = AsPgTx(tx, "PostgresUserRepository::SoftDelete");

        pg_tx.Native().Execute(
            sql::kUsersSoftDelete,
            user_id
        );
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
        auto &pg_tx = AsPgTx(tx, "PostgresUserRepository::UpdatePasswordHash");

        pg_tx.Native().Execute(
            sql::kUsersUpdatePasswordHash,
            user_id,
            new_password_hash
        );
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
