#pragma once

#include <userver/server/handlers/http_handler_json_base.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/http/http_response.hpp>

#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::infra::http {
    class RequestMetaExtractor;
}

namespace smirkly::auth::api::v0::handlers {
    class ResendEmailVerificationHandler final : public userver::server::handlers::HttpHandlerJsonBase {
    public:
        static constexpr std::string_view kName = "handler-resend-email-verification";

        ResendEmailVerificationHandler(const userver::components::ComponentConfig &config,
                                       const userver::components::ComponentContext &context);

        Value HandleRequestJsonThrow(const HttpRequest &request,
                                     const Value &body,
                                     RequestContext &context) const override;

    private:
        smirkly::auth::services::usecases::AuthService &auth_service_;
        smirkly::auth::infra::http::RequestMetaExtractor &request_meta_extractor_;
    };
}
