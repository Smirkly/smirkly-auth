#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smirkly::auth::infra::messaging::smtp {
    enum class TlsMode {
        kNone,
        kStartTls,
        kTls
    };

    struct SmtpConfig {
        std::string host;
        std::uint16_t port{587};
        TlsMode tls_mode{TlsMode::kStartTls};
        std::string username;
        std::string app_password;
        std::chrono::milliseconds connect_timeout_ms{20000};
        std::chrono::milliseconds timeout_ms{30000};
    };

    enum class SmtpErrorKind {
        kNone,
        kAuth,
        kNetwork,
        kTimeout,
        kTls,
        kProtocol,
        kRateLimited,
        kUnknown
    };

    struct SmtpSendResult {
        bool ok{false};
        bool retryable{false};
        SmtpErrorKind kind{SmtpErrorKind::kNone};
        std::string error;
    };

    struct Rfc822Message {
        std::string payload;
    };

    class CurlSmtpClient final {
    public:
        explicit CurlSmtpClient(SmtpConfig config);

        ~CurlSmtpClient();

        CurlSmtpClient(const CurlSmtpClient &) = delete;

        CurlSmtpClient &operator=(const CurlSmtpClient &) = delete;

        CurlSmtpClient(CurlSmtpClient &&) noexcept;

        CurlSmtpClient &operator=(CurlSmtpClient &&) noexcept;

        SmtpSendResult Send(
            const std::string &mail_from,
            const std::vector<std::string> &rcpt_to,
            const Rfc822Message &message
        );

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
