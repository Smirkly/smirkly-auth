#include <auth/api/v0/dto/sign_up_request.hpp>
#include <userver/server/handlers/exceptions.hpp>

namespace smirkly::auth::api::v0::dto {
    SignUpRequest SignUpRequest::FromJson(const userver::formats::json::Value &body) {
        SignUpRequest dto;

        if (body.HasMember("phone")) {
            dto.phone = body["phone"].As<std::string>();
        }

        if (body.HasMember("email")) {
            dto.email = body["email"].As<std::string>();
        }

        if (!body.HasMember("username")) {
            throw userver::server::handlers::ClientError{
                userver::server::handlers::ExternalBody{"'username' is required"}
            };
        }

        if (!body.HasMember("password")) {
            throw userver::server::handlers::ClientError{
                userver::server::handlers::ExternalBody{"'password' is required"}
            };
        }

        dto.username = body["username"].As<std::string>();
        dto.password = body["password"].As<std::string>();

        if (!dto.phone && !dto.email) {
            throw userver::server::handlers::ClientError{
                userver::server::handlers::ExternalBody{"either 'phone' or 'email' must be provided"}
            };
        }

        return dto;
    }
}
