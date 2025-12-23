#pragma once

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::ports {
    class EmailVerificationSender {
    public:
        virtual ~EmailVerificationSender() = default;

        virtual void SendVerificationEmail(const domain::models::User &user, std::string_view code) = 0;
    };
}
