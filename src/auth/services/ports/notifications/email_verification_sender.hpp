#pragma once

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::ports {
    struct VerificationEmail {
        std::string to_email;
        std::string code;
        std::string correlation_id;
        std::string locale{"ru"};
    };

    class EmailVerificationSender {
    public:
        virtual ~EmailVerificationSender() = default;

        virtual void SendVerificationEmail(const VerificationEmail &msg) = 0;
    };
}
