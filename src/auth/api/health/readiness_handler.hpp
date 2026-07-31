#pragma once

#include <memory>
#include <string_view>

#include <userver/dynamic_config/source.hpp>
#include <userver/server/handlers/http_handler_json_base.hpp>
#include <userver/yaml_config/schema.hpp>

USERVER_NAMESPACE_BEGIN
namespace storages::postgres {
class Cluster;
using ClusterPtr = std::shared_ptr<Cluster>;
}  // namespace storages::postgres
USERVER_NAMESPACE_END

namespace smirkly::auth::api::health {

class ReadinessHandler final
    : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName = "handler-health-ready";

  ReadinessHandler(const userver::components::ComponentConfig& config,
                   const userver::components::ComponentContext& context);

  static userver::yaml_config::Schema GetStaticConfigSchema();

  Value HandleRequestJsonThrow(const HttpRequest& request, const Value& body,
                               RequestContext& context) const override;

 private:
  USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
  userver::dynamic_config::Source dynamic_config_source_;
};

}  // namespace smirkly::auth::api::health
