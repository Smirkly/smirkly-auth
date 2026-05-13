#include <auth/services/validation/sign_up_validator.hpp>

#include <stdexcept>
#include <utility>

#include <auth/services/errors/sign_up_errors.hpp>

namespace {
    bool IsLowerAscii(char c) noexcept {
        return c >= 'a' && c <= 'z';
    }

    bool IsUpperAscii(char c) noexcept {
        return c >= 'A' && c <= 'Z';
    }

    bool IsDigitAscii(char c) noexcept {
        return c >= '0' && c <= '9';
    }

    bool IsControlAscii(char c) noexcept {
        return c >= 0 && c < ' ';
    }
}

namespace smirkly::auth::services::validation {
    SignUpValidator::SignUpValidator(SignUpPolicy policy) : policy_(std::move(policy)) {
    }

    void SignUpValidator::ValidatePassword(std::string_view password) const {
        if (password.empty()) {
            throw errors::SignUpValidation("password is empty");
        }
        if (password.size() < policy_.password_min_len) {
            throw errors::SignUpValidation("password is too short");
        }
        if (password.size() > policy_.password_max_len) {
            throw errors::SignUpValidation("password is too long");
        }

        bool has_lower = false;
        bool has_upper = false;
        bool has_digit = false;
        bool has_other = false;

        for (const char c: password) {
            if (IsControlAscii(c) || c == '\x7f') {
                throw errors::SignUpValidation("password must not contain control characters");
            }
            has_lower = has_lower || IsLowerAscii(c);
            has_upper = has_upper || IsUpperAscii(c);
            has_digit = has_digit || IsDigitAscii(c);
            has_other = has_other || (!IsLowerAscii(c) && !IsUpperAscii(c) && !IsDigitAscii(c));
        }

        const auto complexity_classes =
            static_cast<int>(has_lower) +
            static_cast<int>(has_upper) +
            static_cast<int>(has_digit) +
            static_cast<int>(has_other);
        if (complexity_classes < 3) {
            throw errors::SignUpValidation("password must include at least three character classes");
        }
    }

    NormalizedSignUpInput
    SignUpValidator::ValidateAndNormalize(const contracts::SignUpCommand &cmd) const {
        if (policy_.require_email && !cmd.email) {
            throw errors::SignUpValidation("email is required");
        }
        if (policy_.require_phone && !cmd.phone) {
            throw errors::SignUpValidation("phone is required");
        }
        if (policy_.require_contact && !cmd.email && !cmd.phone) {
            throw errors::SignUpValidation("email or phone is required");
        }

        ValidatePassword(cmd.password);

        try {
            NormalizedSignUpInput input{
                .username = domain::value_objects::Username{cmd.username},
                .password = cmd.password,
                .email = std::nullopt,
                .phone = std::nullopt,
            };

            if (cmd.email) {
                input.email = domain::value_objects::Email{*cmd.email};
            }
            if (cmd.phone) {
                input.phone = domain::value_objects::Phone{*cmd.phone};
            }

            return input;
        } catch (const std::invalid_argument &e) {
            throw errors::SignUpValidation(e.what());
        }
    }
}
