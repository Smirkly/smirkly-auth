#pragma once

#include <userver/server/handlers/http_handler_json_base.hpp>

#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::api::v0::handlers {
    class MeHandler final : public userver::server::handlers::HttpHandlerJsonBase {
    public:
        static constexpr std::string_view kName = "handler-auth-me";

        MeHandler(
            const userver::components::ComponentConfig &config,
            const userver::components::ComponentContext &context
        );

        Value HandleRequestJsonThrow(
            const HttpRequest &request,
            const Value &body,
            RequestContext &context
        ) const override;

    private:
        services::usecases::AuthService &auth_service_;
    };
}
