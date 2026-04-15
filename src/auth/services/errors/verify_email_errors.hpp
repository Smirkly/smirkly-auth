#pragma once

#include <stdexcept>

namespace smirkly::auth::services::errors {
    struct DomainError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    struct VerifyEmailError : DomainError {
        using DomainError::DomainError;
    };

    struct UserNotFound : VerifyEmailError {
        using VerifyEmailError::VerifyEmailError;
    };

    struct InvalidCode : VerifyEmailError {
        using VerifyEmailError::VerifyEmailError;
    };

    struct CodeExpired : VerifyEmailError {
        using VerifyEmailError::VerifyEmailError;
    };

    struct AlreadyVerified : VerifyEmailError {
        using VerifyEmailError::VerifyEmailError;
    };
}
