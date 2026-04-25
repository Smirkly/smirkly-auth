#pragma once

#include <stdexcept>
#include <string>

namespace smirkly::auth::services::errors {
    class SignInError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class SignInValidation final : public SignInError {
    public:
        using SignInError::SignInError;
    };

    class InvalidCredentials final : public SignInError {
    public:
        using SignInError::SignInError;
    };

    class EmailNotVerified final : public SignInError {
    public:
        using SignInError::SignInError;
    };
}