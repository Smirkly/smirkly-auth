#include <auth/api/v0/handlers/sign_up_handler.hpp>

#include <userver/server/handlers/exceptions.hpp>
#include <userver/components/component_context.hpp>

#include <string>
#include <string_view>

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace {
    userver::formats::json::Value ErrorResponse(
        std::string_view code,
        std::string_view message
    ) {
        userver::formats::json::ValueBuilder builder;
        builder["code"] = std::string{code};
        builder["message"] = std::string{message};
        return builder.ExtractValue();
    }
}

namespace smirkly::auth::api::v0::handlers {
    SignUpHandler::SignUpHandler(const userver::components::ComponentConfig &config,
                                 const userver::components::ComponentContext &context) : HttpHandlerJsonBase(
            config, context),
        auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()) {
    }

    SignUpHandler::Value SignUpHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        const auto sign_up_dto = api::v0::dto::SignUpRequest::FromJson(body);
        auto sign_up_cmd = infra::mapping::ToDomain(sign_up_dto);

        const auto &user_agent_header = request.GetHeader("User-Agent");
        services::contracts::RequestMeta meta = {
            .ip = request.GetRemoteAddress().PrimaryAddressString(),
            .user_agent = user_agent_header.empty()
                              ? std::nullopt
                              : std::make_optional<std::string>(user_agent_header)
        };

        try {
            auto result = auth_service_.SignUp(sign_up_cmd, meta);
            auto user_dto = infra::mapping::ToUserDto(result.user);

            userver::formats::json::ValueBuilder builder;
            builder["user"] = user_dto.ToJson();

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kCreated);
            return builder.ExtractValue();
        } catch (const services::errors::SignUpValidation &e) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return ErrorResponse("sign_up.validation_failed", e.what());
        } catch (const services::errors::UsernameTaken &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kConflict);
            return ErrorResponse("sign_up.username_taken", "username taken");
        } catch (const services::errors::EmailTaken &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kConflict);
            return ErrorResponse("sign_up.email_taken", "email taken");
        } catch (const services::errors::PhoneTaken &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kConflict);
            return ErrorResponse("sign_up.phone_taken", "phone taken");
        }
    }
};
