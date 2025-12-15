#pragma once

#include <auth/services/ports/email_verification_sender.hpp>

namespace smirkly::auth::infra::security {
    class EmailVerificationSender : public services::ports::EmailVerificationSender {
    public:
        void SendVerificationEmail(const domain::models::User user, std::string_view code) override;
    };
}
