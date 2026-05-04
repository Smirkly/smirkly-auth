#pragma once

#include <stdexcept>

namespace smirkly::auth::services::errors {
    struct AccessTokenError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    struct MissingAccessToken : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct InvalidAccessToken : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct AuthSessionNotFound : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct AuthSessionRevoked : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct AuthSessionExpired : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct AuthUserNotFound : AccessTokenError {
        using AccessTokenError::AccessTokenError;
    };

    struct SessionNotFound : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    struct SessionForbidden : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
}
