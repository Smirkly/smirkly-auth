#include <auth/api/v0/utils/auth_error_mapper.hpp>

#include <stdexcept>

#include <userver/server/http/http_status.hpp>
#include <userver/utest/utest.hpp>

#include <auth/services/errors/change_password_errors.hpp>
#include <auth/services/errors/sign_in_errors.hpp>
#include <auth/services/errors/verify_email_errors.hpp>

namespace {
namespace errors = smirkly::auth::services::errors;
namespace utils = smirkly::auth::api::v0::utils;
using userver::server::http::HttpStatus;

UTEST(AuthErrorMapper, MapsSignInRateLimit) {
  const auto mapped = utils::TryMapAuthError(
      errors::TooManySignInAttempts{"too many sign-in attempts"});

  ASSERT_TRUE(mapped.has_value());
  EXPECT_EQ(mapped->status, HttpStatus::kTooManyRequests);
  EXPECT_EQ(mapped->code, "auth.sign_in.too_many_attempts");
  EXPECT_EQ(mapped->message, "too many sign-in attempts");
}

UTEST(AuthErrorMapper, MapsVerificationRateLimitByContext) {
  const errors::TooManyVerificationAttempts error{
      "too many verification attempts"};

  const auto verify_mapped =
      utils::TryMapAuthError(error, utils::AuthErrorContext::kVerifyEmail);
  const auto resend_mapped = utils::TryMapAuthError(
      error, utils::AuthErrorContext::kResendEmailVerification);

  ASSERT_TRUE(verify_mapped.has_value());
  EXPECT_EQ(verify_mapped->status, HttpStatus::kTooManyRequests);
  EXPECT_EQ(verify_mapped->code, "auth.verify_email.too_many_attempts");

  ASSERT_TRUE(resend_mapped.has_value());
  EXPECT_EQ(resend_mapped->status, HttpStatus::kTooManyRequests);
  EXPECT_EQ(resend_mapped->code,
            "auth.resend_email_verification.too_many_attempts");
}

UTEST(AuthErrorMapper, PreservesValidationMessages) {
  const auto mapped = utils::TryMapAuthError(errors::ChangePasswordValidation{
      "new password must differ from current password"});

  ASSERT_TRUE(mapped.has_value());
  EXPECT_EQ(mapped->status, HttpStatus::kBadRequest);
  EXPECT_EQ(mapped->code, "auth.change_password.validation_failed");
  EXPECT_EQ(mapped->message, "new password must differ from current password");
}

UTEST(AuthErrorMapper, LeavesUnknownErrorsUnmapped) {
  EXPECT_FALSE(utils::TryMapAuthError(std::runtime_error{"boom"}).has_value());
}

}  // namespace
