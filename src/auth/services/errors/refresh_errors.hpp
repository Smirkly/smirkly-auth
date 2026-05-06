#pragma once

#include <stdexcept>

namespace smirkly::auth::services::errors {
    class RefreshError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class InvalidRefreshToken final : public RefreshError {
    public:
        using RefreshError::RefreshError;
    };

    class RefreshSessionNotFound final : public RefreshError {
    public:
        using RefreshError::RefreshError;
    };

    class RefreshSessionRevoked final : public RefreshError {
    public:
        using RefreshError::RefreshError;
    };

    class RefreshSessionExpired final : public RefreshError {
    public:
        using RefreshError::RefreshError;
    };
}
