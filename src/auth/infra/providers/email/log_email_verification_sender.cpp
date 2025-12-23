#include <auth/infra/providers/email/log_email_verification_sender.hpp>

namespace smirkly::auth::infra::providers::email {
    void EmailVerificationSender::SendVerificationEmail(const domain::models::User &user,
                                                        std::string_view code) {
    }
}
