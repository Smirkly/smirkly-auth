#pragma once

#include <stdexcept>

namespace smirkly::auth::services::errors {
    class ChangePasswordError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class ChangePasswordValidation final : public ChangePasswordError {
    public:
        using ChangePasswordError::ChangePasswordError;
    };

    class InvalidCurrentPassword final : public ChangePasswordError {
    public:
        using ChangePasswordError::ChangePasswordError;
    };
}
