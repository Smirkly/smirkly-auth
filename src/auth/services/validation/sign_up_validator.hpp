#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/domain/value_objects/email.hpp>
#include <auth/domain/value_objects/phone.hpp>
#include <auth/domain/value_objects/username.hpp>
#include <auth/services/contracts/sign_up.hpp>
#include <auth/services/policies/sign_up_policy.hpp>

namespace smirkly::auth::services::validation {
    struct NormalizedSignUpInput final {
        domain::value_objects::Username username;
        std::string password;
        std::optional<domain::value_objects::Email> email;
        std::optional<domain::value_objects::Phone> phone;
    };

    class SignUpValidator final {
    public:
        explicit SignUpValidator(policies::SignUpPolicy policy = {});

        [[nodiscard]] NormalizedSignUpInput ValidateAndNormalize(const contracts::SignUpCommand &cmd) const;

        void ValidatePassword(std::string_view password) const;

    private:
        policies::SignUpPolicy policy_;
    };
}
