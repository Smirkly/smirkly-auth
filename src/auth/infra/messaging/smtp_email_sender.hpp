#pragma once

#include <string>

#include <auth/infra/messaging/smtp/curl_smtp_client.hpp>

namespace smirkly::auth::infra::messaging {
    class SmtpEmailSender final {
    public:
        SmtpEmailSender(smtp::SmtpConfig smtp_config, std::string from_email, std::string from_name = {});

        smtp::SmtpSendResult SendPlaintext(
            const std::string &to_email,
            const std::string &subject,
            const std::string &body
        );

        smtp::SmtpSendResult SendVerificationCode(
            const std::string &to_email,
            const std::string &code
        );

    private:
        smtp::CurlSmtpClient client_;
        std::string from_email_;
        std::string from_name_;
    };
}
