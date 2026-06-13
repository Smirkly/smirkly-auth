#pragma once

namespace smirkly::auth::services::policies {
    struct SignInPolicy final {
        bool require_verified_email{false};
    };
}
