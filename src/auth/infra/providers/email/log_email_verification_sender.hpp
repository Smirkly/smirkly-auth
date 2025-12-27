#pragma once

#include <auth/domain/models/user.hpp>
#include <auth/services/ports/email_verification_sender.hpp>

namespace smirkly::auth::infra::providers::email {
    class EmailVerificationSender final : public services::ports::EmailVerificationSender {
    public:
        void SendVerificationEmail(const services::ports::VerificationEmail &msg) override;
    };
}
