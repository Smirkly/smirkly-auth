#include <auth/api/v0/dto/sign_in_request.hpp>

namespace smirkly::auth::api::v0::dto {
    SignInRequest Parse(const userver::formats::json::Value &value,
                        userver::formats::parse::To<SignInRequest>) {
        SignInRequest dto;
        dto.username = value["username"].As<std::optional<std::string> >();
        dto.email = value["email"].As<std::optional<std::string> >();
        dto.phone = value["phone"].As<std::optional<std::string> >();
        dto.password = value["password"].As<std::string>();
        return dto;
    }
}
