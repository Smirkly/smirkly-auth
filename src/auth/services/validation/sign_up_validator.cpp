#include <auth/services/validation/sign_up_validator.hpp>

namespace smirkly::auth::services {
    validation::SignUpValidator::SignUpValidator(SignUpPolicy policy) : policy_(std::move(policy)) {
    }


    [[nodiscard]] NormalizedSignUpInput
    validation::SignUpValidator::ValidateAndNormalize(const services::SignUpCommand &cmd) const {
    }
}
