#include <auth/api/health/readiness_handler.hpp>

#include <exception>
#include <string>
#include <utility>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/logging/log.hpp>
#include <userver/server/http/http_status.hpp>
#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/storages/postgres/query.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/config/auth_dynamic_config.hpp>

namespace smirkly::auth::api::health {
namespace {

namespace pgsql = USERVER_NAMESPACE::storages::postgres;

constexpr int kExpectedSchemaVersion = 11;

struct CheckResult final {
  bool ok{false};
  std::string message;
  userver::formats::json::Value details;
};

userver::formats::json::ValueBuilder MakeCheckBuilder(
    const CheckResult& check) {
  userver::formats::json::ValueBuilder builder;
  builder["ok"] = check.ok;
  builder["message"] = check.message;
  if (!check.details.IsMissing()) {
    builder["details"] = check.details;
  }
  return builder;
}

CheckResult CheckPostgres(const pgsql::ClusterPtr& cluster) {
  try {
    const auto result = cluster->Execute(
        pgsql::ClusterHostType::kMaster,
        pgsql::Query{"SELECT 1", pgsql::Query::Name{"health.postgres.ping"},
                     pgsql::Query::LogMode::kNameOnly});

    const auto value = result.AsSingleRow<int>();
    if (value != 1) {
      return {.ok = false,
              .message = "unexpected postgres ping result",
              .details = {}};
    }

    return {.ok = true, .message = "postgres is reachable", .details = {}};
  } catch (const std::exception& e) {
    LOG_WARNING() << "Postgres readiness check failed: " << e.what();
    return {.ok = false, .message = "postgres check failed", .details = {}};
  }
}

CheckResult CheckMigrations(const pgsql::ClusterPtr& cluster) {
  try {
    const auto schema_result = cluster->Execute(
        pgsql::ClusterHostType::kMaster,
        pgsql::Query{R"SQL(
SELECT
  to_regclass('public.users') IS NOT NULL
  AND to_regclass('public.devices') IS NOT NULL
  AND to_regclass('public.sessions') IS NOT NULL
  AND to_regclass('public.email_outbox') IS NOT NULL
  AND to_regclass('public.email_verifications') IS NOT NULL
  AND to_regclass('public.email_verification_attempts') IS NOT NULL
  AND to_regclass('public.sign_in_attempts') IS NOT NULL
  AND to_regclass('public.password_resets') IS NOT NULL
  AND to_regclass('public.password_reset_attempts') IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'email_outbox'
      AND column_name = 'lease_id'
  ) AS schema_ready,
  to_regclass('public.schema_migrations') IS NOT NULL AS has_schema_migrations
)SQL",
                     pgsql::Query::Name{"health.postgres.schema"},
                     pgsql::Query::LogMode::kNameOnly});

    const auto row = schema_result.Front();
    const auto schema_ready = row["schema_ready"].As<bool>();
    const auto has_schema_migrations = row["has_schema_migrations"].As<bool>();

    userver::formats::json::ValueBuilder details;
    details["schema_ready"] = schema_ready;
    details["has_schema_migrations"] = has_schema_migrations;
    details["expected_version"] = kExpectedSchemaVersion;

    if (!schema_ready) {
      return {.ok = false,
              .message = "required auth schema objects are missing",
              .details = details.ExtractValue()};
    }

    if (!has_schema_migrations) {
      details["mode"] = "schema-only";
      return {.ok = true,
              .message = "schema objects are present",
              .details = details.ExtractValue()};
    }

    const auto migration_result = cluster->Execute(
        pgsql::ClusterHostType::kMaster,
        pgsql::Query{"SELECT version, dirty FROM schema_migrations ORDER BY "
                     "version DESC LIMIT 1",
                     pgsql::Query::Name{"health.postgres.schema_migrations"},
                     pgsql::Query::LogMode::kNameOnly});

    if (migration_result.IsEmpty()) {
      details["mode"] = "schema-migrations";
      return {.ok = false,
              .message = "schema_migrations is empty",
              .details = details.ExtractValue()};
    }

    const auto migration_row = migration_result.Front();
    const auto version = migration_row["version"].As<int>();
    const auto dirty = migration_row["dirty"].As<bool>();
    details["mode"] = "schema-migrations";
    details["version"] = version;
    details["dirty"] = dirty;

    if (dirty) {
      return {.ok = false,
              .message = "schema_migrations is dirty",
              .details = details.ExtractValue()};
    }

    if (version < kExpectedSchemaVersion) {
      return {
          .ok = false,
          .message = "schema_migrations version is behind binary expectation",
          .details = details.ExtractValue()};
    }

    return {.ok = true,
            .message = "schema migrations are current",
            .details = details.ExtractValue()};
  } catch (const std::exception& e) {
    LOG_WARNING() << "Migration readiness check failed: " << e.what();
    return {.ok = false, .message = "migration check failed", .details = {}};
  }
}

CheckResult CheckDynamicConfig(userver::dynamic_config::Source source) {
  try {
    const auto snapshot = source.GetSnapshot();
    const auto& auth_config = snapshot[config::kAuthRuntimeConfig];
    const auto& outbox_config = snapshot[config::kEmailOutboxRuntimeConfig];

    userver::formats::json::ValueBuilder details;
    details["sign_in_rate_limit_window_seconds"] =
        auth_config.sign_in.rate_limit_window.count();
    details["email_outbox_batch_size"] = outbox_config.batch_size;

    if (auth_config.sign_in.rate_limit_window.count() <= 0 ||
        outbox_config.batch_size == 0) {
      return {.ok = false,
              .message = "dynamic config contains invalid runtime values",
              .details = details.ExtractValue()};
    }

    return {.ok = true,
            .message = "dynamic config snapshot is readable",
            .details = details.ExtractValue()};
  } catch (const std::exception& e) {
    LOG_WARNING() << "Dynamic config readiness check failed: " << e.what();
    return {
        .ok = false, .message = "dynamic config check failed", .details = {}};
  }
}

}  // namespace

userver::yaml_config::Schema ReadinessHandler::GetStaticConfigSchema() {
  return userver::yaml_config::MergeSchemas<HttpHandlerJsonBase>(R"(
type: object
description: Auth readiness probe handler
additionalProperties: false
properties:
  postgres-component:
    type: string
    description: Name of Postgres component to probe
    default: postgres-auth
)");
}

ReadinessHandler::ReadinessHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context, true),
      pg_cluster_(
          context
              .FindComponent<userver::components::Postgres>(
                  config["postgres-component"].As<std::string>("postgres-auth"))
              .GetCluster()),
      dynamic_config_source_(
          context.FindComponent<userver::components::DynamicConfig>()
              .GetSource()) {}

ReadinessHandler::Value ReadinessHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value&, RequestContext&) const {
  const auto postgres = CheckPostgres(pg_cluster_);
  const auto migrations = CheckMigrations(pg_cluster_);
  const auto dynamic_config = CheckDynamicConfig(dynamic_config_source_);
  const bool ok = postgres.ok && migrations.ok && dynamic_config.ok;

  request.GetHttpResponse().SetStatus(
      ok ? userver::server::http::HttpStatus::kOk
         : userver::server::http::HttpStatus::kServiceUnavailable);

  userver::formats::json::ValueBuilder response;
  response["status"] = ok ? "ok" : "degraded";
  response["checks"]["postgres"] = MakeCheckBuilder(postgres).ExtractValue();
  response["checks"]["migrations"] =
      MakeCheckBuilder(migrations).ExtractValue();
  response["checks"]["dynamic_config"] =
      MakeCheckBuilder(dynamic_config).ExtractValue();

  return response.ExtractValue();
}

}  // namespace smirkly::auth::api::health
