#pragma once

#include <exception>
#include <optional>
#include <string>
#include <string_view>

#include <userver/formats/json/value.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/json_error.hpp>
#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/change_password_errors.hpp>
#include <auth/services/errors/password_reset_errors.hpp>
#include <auth/services/errors/refresh_errors.hpp>
#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>

namespace smirkly::auth::api::v0::utils {

enum class AuthErrorContext {
  kGeneric,
  kVerifyEmail,
  kResendEmailVerification,
};

struct HttpError final {
  userver::server::http::HttpStatus status;
  std::string code;
  std::string message;
};

[[nodiscard]] inline std::optional<HttpError> TryMapAuthError(
    const std::exception& error,
    AuthErrorContext context = AuthErrorContext::kGeneric) {
  using userver::server::http::HttpStatus;
  namespace service_errors = smirkly::auth::services::errors;

  if (const auto* e =
          dynamic_cast<const service_errors::SignUpValidation*>(&error)) {
    return HttpError{HttpStatus::kBadRequest, "sign_up.validation_failed",
                     e->what()};
  }
  if (dynamic_cast<const service_errors::UsernameTaken*>(&error)) {
    return HttpError{HttpStatus::kConflict, "sign_up.username_taken",
                     "username taken"};
  }
  if (dynamic_cast<const service_errors::EmailTaken*>(&error)) {
    return HttpError{HttpStatus::kConflict, "sign_up.email_taken",
                     "email taken"};
  }
  if (dynamic_cast<const service_errors::PhoneTaken*>(&error)) {
    return HttpError{HttpStatus::kConflict, "sign_up.phone_taken",
                     "phone taken"};
  }

  if (const auto* e =
          dynamic_cast<const service_errors::SignInValidation*>(&error)) {
    return HttpError{HttpStatus::kBadRequest, "auth.sign_in.validation_failed",
                     e->what()};
  }
  if (dynamic_cast<const service_errors::InvalidCredentials*>(&error)) {
    return HttpError{HttpStatus::kUnauthorized, "auth.invalid_credentials",
                     "invalid credentials"};
  }
  if (dynamic_cast<const service_errors::EmailNotVerified*>(&error)) {
    return HttpError{HttpStatus::kForbidden, "auth.email_not_verified",
                     "email is not verified"};
  }
  if (dynamic_cast<const service_errors::TooManySignInAttempts*>(&error)) {
    return HttpError{HttpStatus::kTooManyRequests,
                     "auth.sign_in.too_many_attempts",
                     "too many sign-in attempts"};
  }

  if (dynamic_cast<const service_errors::UserNotFound*>(&error)) {
    return HttpError{HttpStatus::kNotFound, "auth.verify_email.user_not_found",
                     "user not found"};
  }
  if (dynamic_cast<const service_errors::InvalidCode*>(&error)) {
    return HttpError{HttpStatus::kBadRequest, "auth.verify_email.invalid_code",
                     "invalid verification code"};
  }
  if (dynamic_cast<const service_errors::TooManyVerificationAttempts*>(
          &error)) {
    if (context == AuthErrorContext::kResendEmailVerification) {
      return HttpError{HttpStatus::kTooManyRequests,
                       "auth.resend_email_verification.too_many_attempts",
                       "too many verification attempts"};
    }

    return HttpError{HttpStatus::kTooManyRequests,
                     "auth.verify_email.too_many_attempts",
                     "too many verification attempts"};
  }
  if (dynamic_cast<const service_errors::CodeExpired*>(&error)) {
    return HttpError{HttpStatus::kGone, "auth.verify_email.code_expired",
                     "verification code expired or not found"};
  }
  if (dynamic_cast<const service_errors::VerifyEmailError*>(&error)) {
    return HttpError{HttpStatus::kBadRequest, "auth.verify_email.failed",
                     "email verification failed"};
  }

  if (const auto* e =
          dynamic_cast<const service_errors::PasswordResetValidation*>(
              &error)) {
    return HttpError{HttpStatus::kBadRequest,
                     "auth.password_reset.validation_failed", e->what()};
  }
  if (dynamic_cast<const service_errors::TooManyPasswordResetAttempts*>(
          &error)) {
    return HttpError{HttpStatus::kTooManyRequests,
                     "auth.password_reset.too_many_attempts",
                     "too many password reset attempts"};
  }
  if (dynamic_cast<const service_errors::PasswordResetExpired*>(&error)) {
    return HttpError{HttpStatus::kGone, "auth.password_reset.expired",
                     "password reset token expired or not found"};
  }
  if (dynamic_cast<const service_errors::InvalidPasswordResetToken*>(&error)) {
    return HttpError{HttpStatus::kBadRequest,
                     "auth.password_reset.invalid_token",
                     "invalid password reset token"};
  }

  if (dynamic_cast<const service_errors::MissingAccessToken*>(&error)) {
    return HttpError{HttpStatus::kUnauthorized, "auth.missing_access_token",
                     "missing access token"};
  }
  if (dynamic_cast<const service_errors::InvalidCurrentPassword*>(&error)) {
    return HttpError{HttpStatus::kUnauthorized, "auth.invalid_current_password",
                     "invalid current password"};
  }
  if (const auto* e =
          dynamic_cast<const service_errors::ChangePasswordValidation*>(
              &error)) {
    return HttpError{HttpStatus::kBadRequest,
                     "auth.change_password.validation_failed", e->what()};
  }
  if (dynamic_cast<const service_errors::AccessTokenError*>(&error)) {
    return HttpError{HttpStatus::kUnauthorized, "auth.invalid_access_token",
                     "invalid access token"};
  }
  if (dynamic_cast<const service_errors::SessionForbidden*>(&error)) {
    return HttpError{HttpStatus::kForbidden, "auth.session_forbidden",
                     "session belongs to another user"};
  }
  if (dynamic_cast<const service_errors::SessionNotFound*>(&error)) {
    return HttpError{HttpStatus::kNotFound, "auth.session_not_found",
                     "session not found"};
  }

  if (dynamic_cast<const service_errors::RefreshError*>(&error)) {
    return HttpError{HttpStatus::kUnauthorized, "auth.invalid_refresh_token",
                     "invalid refresh token"};
  }

  return std::nullopt;
}

template <typename HttpRequest>
[[nodiscard]] userver::formats::json::Value ErrorResponse(
    const HttpRequest& request, const HttpError& error) {
  request.GetHttpResponse().SetStatus(error.status);
  return ErrorResponse(error.code, error.message);
}

template <typename HttpRequest>
[[nodiscard]] userver::formats::json::Value AuthErrorResponse(
    const HttpRequest& request, const std::exception& error,
    AuthErrorContext context = AuthErrorContext::kGeneric) {
  const auto mapped_error = TryMapAuthError(error, context);
  if (!mapped_error) {
    throw;
  }

  return ErrorResponse(request, *mapped_error);
}

}  // namespace smirkly::auth::api::v0::utils
