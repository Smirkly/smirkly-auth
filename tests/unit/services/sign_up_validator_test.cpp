#include <auth/services/errors/sign_up_errors.hpp>
#include <auth/services/validation/sign_up_validator.hpp>

#include <userver/utest/utest.hpp>

namespace {
    using smirkly::auth::services::contracts::SignUpCommand;
    using smirkly::auth::services::errors::SignUpValidation;
    using smirkly::auth::services::validation::SignUpValidator;

    void ExpectValidationError(const SignUpValidator &validator, const SignUpCommand &cmd) {
        try {
            static_cast<void>(validator.ValidateAndNormalize(cmd));
            FAIL() << "expected SignUpValidation";
        } catch (const SignUpValidation &) {
        }
    }

    UTEST(SignUpValidator, NormalizesValidInput) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "  Capy_Name  ",
            .password = "StrongPass123!",
            .phone = "+7 (999) 000-00-00",
            .email = "  CAPY@Example.COM  ",
        };

        const auto input = validator.ValidateAndNormalize(cmd);

        EXPECT_EQ(input.username.Value(), "capy_name");
        ASSERT_TRUE(input.email.has_value());
        EXPECT_EQ(input.email->Value(), "capy@example.com");
        ASSERT_TRUE(input.phone.has_value());
        EXPECT_EQ(input.phone->Value(), "+79990000000");
        EXPECT_EQ(input.password, "StrongPass123!");
    }

    UTEST(SignUpValidator, RejectsMissingContact) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "capy",
            .password = "StrongPass123!",
        };

        ExpectValidationError(validator, cmd);
    }

    UTEST(SignUpValidator, RejectsWeakPassword) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "capy",
            .password = "password",
            .email = "capy@example.com",
        };

        ExpectValidationError(validator, cmd);
    }

    UTEST(SignUpValidator, RejectsInvalidUsername) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "_bad-name",
            .password = "StrongPass123!",
            .email = "capy@example.com",
        };

        ExpectValidationError(validator, cmd);
    }

    UTEST(SignUpValidator, RejectsInvalidEmail) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "capy",
            .password = "StrongPass123!",
            .email = "invalid-email",
        };

        ExpectValidationError(validator, cmd);
    }

    UTEST(SignUpValidator, RejectsInvalidPhone) {
        SignUpValidator validator;
        SignUpCommand cmd{
            .username = "capy",
            .password = "StrongPass123!",
            .phone = "79990000000",
        };

        ExpectValidationError(validator, cmd);
    }
}
