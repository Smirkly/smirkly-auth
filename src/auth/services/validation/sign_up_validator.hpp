#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include <auth/domain/value_objects/email.hpp>
#include <auth/domain/value_objects/phone.hpp>
#include <auth/domain/value_objects/username.hpp>
#include <auth/services/contracts/sign_up.hpp>

namespace smirkly::auth::services::validation {
    struct SignUpPolicy final {
        std::size_t password_min_len{8};
        std::size_t password_max_len{72};

        bool require_email{false};
        bool require_phone{false};
        bool require_contact{true};
    };

    struct NormalizedSignUpInput final {
        domain::value_objects::Username username;
        std::string password;
        std::optional<domain::value_objects::Email> email;
        std::optional<domain::value_objects::Phone> phone;
    };

    class SignUpValidator final {
    public:
        explicit SignUpValidator(SignUpPolicy policy = {});

        [[nodiscard]] NormalizedSignUpInput ValidateAndNormalize(const contracts::SignUpCommand &cmd) const;

    private:
        SignUpPolicy policy_;
    };
}
