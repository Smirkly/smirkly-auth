#pragma once

#include <auth/services/ports/email_verification_sender.hpp>
#include <auth/domain/models/user.hpp>

namespace smirkly::auth::infra::providers::email {
    class EmailVerificationSender final : public services::ports::EmailVerificationSender {
    public:
        void SendVerificationEmail(const domain::models::User &user, std::string_view code) override;
    };
}
