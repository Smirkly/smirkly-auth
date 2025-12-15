// src/main.cpp
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/components/component_list.hpp>
#include <userver/clients/dns/component.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/server/handlers/tests_control.hpp>
#include <userver/testsuite/testsuite_support.hpp>
#include <userver/congestion_control/component.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/utils/daemon_run.hpp>
#include <auth/api/v0/handlers/sign_up_handler.hpp>
#include <auth/components/auth_service_component.hpp>
#include <userver/storages/redis/component.hpp>

int main(int argc, char *argv[]) {
    auto components =
            userver::components::MinimalServerComponentList()
            .Append<userver::components::Postgres>("postgres-auth")
            /*.Append<userver::components::Redis>("redis-auth")*/
            .Append<userver::clients::dns::Component>()
            .Append<userver::components::TestsuiteSupport>()
            .Append<userver::server::handlers::TestsControl>()
            .Append<userver::congestion_control::Component>()
            .Append<smirkly::auth::components::AuthServiceComponent>()
            .Append<smirkly::auth::api::v0::handlers::SignUpHandler>();

    return userver::utils::DaemonMain(argc, argv, components);
}
