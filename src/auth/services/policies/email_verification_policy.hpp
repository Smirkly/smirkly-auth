#pragma once

#include <chrono>
#include <cstddef>

namespace smirkly::auth::services::policies {
    struct EmailVerificationPolicy final {
        std::size_t max_code_attempts{5};
        std::chrono::seconds rate_limit_window{std::chrono::minutes{15}};
        std::size_t max_attempts_per_email{5};
        std::size_t max_attempts_per_user{5};
        std::size_t max_attempts_per_ip{50};
    };
}
