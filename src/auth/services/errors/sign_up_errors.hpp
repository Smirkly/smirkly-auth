#pragma once

#include <stdexcept>
#include <string>

namespace smirkly::auth::services::errors {
    struct SignUpConflict : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    struct UsernameTaken : SignUpConflict {
        using SignUpConflict::SignUpConflict;
    };

    struct EmailTaken : SignUpConflict {
        using SignUpConflict::SignUpConflict;
    };

    struct PhoneTaken : SignUpConflict {
        using SignUpConflict::SignUpConflict;
    };

    struct SignUpValidation : SignUpConflict {
        using SignUpConflict::SignUpConflict;
    };
}
