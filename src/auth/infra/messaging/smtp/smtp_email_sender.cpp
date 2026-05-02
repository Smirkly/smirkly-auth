#include <auth/infra/messaging/smtp/smtp_email_sender.hpp>

#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <string_view>
#include <vector>

namespace smirkly::auth::infra::messaging {
    namespace {
        bool ContainsCrlf(std::string_view s) {
            // Prevent header injection via CR/LF in envelope/header fields.
            return s.find('\r') != std::string_view::npos || s.find('\n') != std::string_view::npos;
        }

        std::string ExtractDomain(std::string_view email) {
            const auto at = email.find('@');
            if (at == std::string_view::npos || at + 1 >= email.size()) return "localhost";
            return std::string(email.substr(at + 1));
        }

        std::string NowRfc2822DateUtc() {
            using namespace std::chrono;

            const auto now = system_clock::now();
            const std::time_t t = system_clock::to_time_t(now);

            std::tm tm{};
#if defined(_WIN32)
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif

            std::ostringstream oss;
            oss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S +0000");
            return oss.str();
        }

        std::string RandomHex(std::size_t bytes) {
            static thread_local std::mt19937_64 rng{std::random_device{}()};
            std::uniform_int_distribution<unsigned int> dist(0, 255);

            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (std::size_t i = 0; i < bytes; ++i) {
                const auto v = dist(rng);
                oss << std::setw(2) << v;
            }
            return oss.str();
        }

        std::string MakeMessageId(std::string_view from_email) {
            return "<" + RandomHex(16) + "." + RandomHex(8) + "@" + ExtractDomain(from_email) + ">";
        }

        std::string FormatMailbox(std::string_view email, std::string_view display_name) {
            // Conservative display name formatting: avoid RFC2047 encoding/quoting complexity.
            if (display_name.empty()) return std::string(email);

            for (unsigned char c: display_name) {
                if (!(std::isalnum(c) || c == ' ' || c == '_' || c == '.' || c == '-')) {
                    return std::string(email);
                }
            }

            return std::string(display_name) + " <" + std::string(email) + ">";
        }

        smtp::Rfc822Message BuildPlaintextRfc822(
            std::string_view from_email,
            std::string_view from_name,
            std::string_view to_email,
            std::string_view subject,
            std::string_view body
        ) {
            // RFC5322 message; headers and body use CRLF.
            std::ostringstream out;

            out << "From: " << FormatMailbox(from_email, from_name) << "\r\n";
            out << "To: " << std::string(to_email) << "\r\n";
            out << "Subject: " << std::string(subject) << "\r\n";
            // Date/Message-ID improve deliverability and debugging.
            out << "Date: " << NowRfc2822DateUtc() << "\r\n";
            out << "Message-ID: " << MakeMessageId(from_email) << "\r\n";
            out << "MIME-Version: 1.0\r\n";
            out << "Content-Type: text/plain; charset=UTF-8\r\n";
            out << "Content-Transfer-Encoding: 8bit\r\n";
            out << "\r\n";

            for (size_t i = 0; i < body.size(); ++i) {
                const char c = body[i];
                if (c == '\n') {
                    if (i == 0 || body[i - 1] != '\r') out << '\r';
                    out << '\n';
                } else {
                    out << c;
                }
            }

            out << "\r\n";

            return smtp::Rfc822Message{out.str()};
        }
    }

    SmtpEmailSender::SmtpEmailSender(smtp::SmtpConfig smtp_config, std::string from_email, std::string from_name)
        : client_(std::move(smtp_config)),
          from_email_(std::move(from_email)),
          from_name_(std::move(from_name)) {
    }

    smtp::SmtpSendResult SmtpEmailSender::SendPlaintext(
        const std::string &to_email,
        const std::string &subject,
        const std::string &body
    ) {
        if (from_email_.empty()) {
            return {false, false, smtp::SmtpErrorKind::kProtocol, "From email is empty"};
        }
        if (to_email.empty()) {
            return {false, false, smtp::SmtpErrorKind::kProtocol, "To email is empty"};
        }
        if (ContainsCrlf(from_email_) || ContainsCrlf(to_email) || ContainsCrlf(subject) || ContainsCrlf(from_name_)) {
            return {false, false, smtp::SmtpErrorKind::kProtocol, "CRLF in headers is not allowed"};
        }

        const auto msg = BuildPlaintextRfc822(from_email_, from_name_, to_email, subject, body);

        std::vector<std::string> rcpt{to_email};
        return client_.Send(from_email_, rcpt, msg);
    }

    smtp::SmtpSendResult SmtpEmailSender::SendVerificationCode(
        const std::string &to_email,
        const std::string &code
    ) {
        const std::string subject = "Smirkly verification code";
        const std::string body =
                "Your verification code: " + code + "\r\n\r\n"
                "If you didn't request it, ignore this message.\r\n";

        return SendPlaintext(to_email, subject, body);
    }
}
