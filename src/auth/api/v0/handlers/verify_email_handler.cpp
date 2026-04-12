#include <auth/api/v0/handlers/verify_email_handler.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#include <userver/components/component_context.hpp>

#include <auth/components/auth_service_component.hpp>
#include <auth/services/errors/verify_email_errors.hpp>


namespace smirkly::auth::api::v0::handlers {
    VerifyEmailHandler::VerifyEmailHandler(const userver::components::ComponentConfig &config,
                                           const userver::components::ComponentContext &
                                           context)
        : HttpHandlerBase(config, context),
          auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()) {
    }

    std::string VerifyEmailHandler::HandleRequestThrow(
        const userver::server::http::HttpRequest &request,
        userver::server::request::RequestContext &context
    )
    const {
        const std::string_view email = request.GetArg("email");
        const std::string_view code = request.GetArg("code");

        if (email.empty() || code.empty()) {
            throw userver::server::handlers::ClientError(userver::server::handlers::ExternalBody{
                "Missing email or code"
            });
        }

        if (email.size() > 320 || email.find('@') == std::string::npos) {
            throw userver::server::handlers::ClientError(userver::server::handlers::ExternalBody{
                "Invalid email format"
            });
        }

        const bool invalid_code = code.size() != 6 || !std::all_of(
                                      code.begin(), code.end(),
                                      [](unsigned char c) { return std::isdigit(c); }
                                  );

        if (invalid_code) {
            throw userver::server::handlers::ClientError(userver::server::handlers::ExternalBody{
                "Invalid code format"
            });
        }

        const auto cmd = services::VerifyEmailCommand{
            .email = std::string{email},
            .code = std::string{code}
        };

        try {
            auth_service_.VerifyEmail(cmd);
        } catch (const services::errors::AlreadyVerified &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
            return {};
        } catch (const services::errors::UserNotFound &) {
            throw userver::server::handlers::ResourceNotFound(userver::server::handlers::ExternalBody{
                "User not found"
            });
        } catch (const services::errors::InvalidCode &) {
            throw userver::server::handlers::ClientError(userver::server::handlers::ExternalBody{
                "Invalid verification code"
            });
        } catch (const services::errors::CodeExpired &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kGone);
            return {};
        } catch (const services::errors::VerifyEmailError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return {};
        }

        request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
        return {};
    }
}
