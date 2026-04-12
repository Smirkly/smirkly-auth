#pragma once

#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/http/http_response.hpp>

#include <auth/services/usecases/auth_service.hpp>


namespace smirkly::auth::api::v0::handlers {
    class VerifyEmailHandler final : public userver::server::handlers::HttpHandlerBase {
    public:
        static constexpr std::string_view kName = "handler-verify-email";

        VerifyEmailHandler(const userver::components::ComponentConfig &config,
                           const userver::components::ComponentContext &context);

        std::string HandleRequestThrow(const userver::server::http::HttpRequest &request,
                                       userver::server::request::RequestContext &context) const override;

    private:
        smirkly::auth::services::usecases::AuthService &auth_service_;
    };
}
