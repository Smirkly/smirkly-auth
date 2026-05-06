#include <userver/clients/dns/component.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/components/component_list.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/congestion_control/component.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/server/handlers/tests_control.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/testsuite/testsuite_support.hpp>
#include <userver/utils/daemon_run.hpp>

#include <auth/api/v0/handlers/jwks_handler.hpp>
#include <auth/api/v0/handlers/me_handler.hpp>
#include <auth/api/v0/handlers/refresh_token_handler.hpp>
#include <auth/api/v0/handlers/session_revoke_handler.hpp>
#include <auth/api/v0/handlers/sessions_handler.hpp>
#include <auth/api/v0/handlers/sign_in_handler.hpp>
#include <auth/api/v0/handlers/sign_up_handler.hpp>
#include <auth/api/v0/handlers/verify_email_handler.hpp>
#include <auth/components/auth_infra_component.hpp>
#include <auth/components/auth_security_component.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/components/email_outbox_worker_component.hpp>

int main(int argc, char* argv[]) {
  auto components =
      userver::components::MinimalServerComponentList()
          .Append<userver::components::Postgres>("postgres-auth")
          .Append<userver::clients::dns::Component>()
          .Append<userver::components::TestsuiteSupport>()
          .Append<userver::server::handlers::TestsControl>()
          .Append<userver::congestion_control::Component>()
          .Append<smirkly::auth::components::AuthInfraComponent>()
          .Append<smirkly::auth::components::AuthSecurityComponent>()
          .Append<smirkly::auth::components::EmailOutboxWorkerComponent>()
          .Append<smirkly::auth::components::AuthServiceComponent>()
          .Append<smirkly::auth::api::v0::handlers::SignUpHandler>()
          .Append<smirkly::auth::api::v0::handlers::VerifyEmailHandler>()
          .Append<smirkly::auth::api::v0::handlers::SignInHandler>()
          .Append<smirkly::auth::api::v0::handlers::RefreshHandler>()
          .Append<smirkly::auth::api::v0::handlers::MeHandler>()
          .Append<smirkly::auth::api::v0::handlers::SessionsHandler>()
          .Append<smirkly::auth::api::v0::handlers::SessionRevokeHandler>()
          .Append<smirkly::auth::api::v0::handlers::JwksHandler>();

  return userver::utils::DaemonMain(argc, argv, components);
}
