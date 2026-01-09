#include <auth/infra/messaging/smtp/curl_smtp_client.hpp>

#include <cstring>
#include <mutex>
#include <sstream>
#include <string_view>
#include <utility>

#include <curl/curl.h>

namespace smirkly::auth::infra::messaging::smtp {
    namespace {
        void EnsureCurlGlobalInit() {
            static std::once_flag once;
            std::call_once(once, [] {
                curl_global_init(CURL_GLOBAL_DEFAULT);
                std::atexit([] { curl_global_cleanup(); });
            });
        }

        std::string MakeUrl(const SmtpConfig &cfg) {
            std::ostringstream oss;
            if (cfg.tls_mode == TlsMode::kTls) {
                oss << "smtps://";
            } else {
                oss << "smtp://";
            }
            oss << cfg.host << ":" << cfg.port;
            return oss.str();
        }

        std::string EnsureAngleBrackets(const std::string &s) {
            if (!s.empty() && s.front() == '<' && s.back() == '>') return s;
            return "<" + s + ">";
        }

        bool LooksLikeCrLfText(std::string_view s) {
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\n') {
                    if (i == 0 || s[i - 1] != '\r') return false;
                }
            }
            return true;
        }


        // libcurl reads DATA payload via callback
        // RFC822 payload must use CRLF line endings
        struct UploadCtx {
            const char *data{nullptr};
            size_t left{0};
        };

        size_t ReadCallback(char *ptr, size_t size, size_t nmemb, void *userp) {
            auto *up = static_cast<UploadCtx *>(userp);
            const size_t cap = size * nmemb;
            const size_t n = (up->left < cap) ? up->left : cap;

            if (n > 0) {
                std::memcpy(ptr, up->data, n);
                up->data += n;
                up->left -= n;
            }
            return n;
        }

        SmtpSendResult MapCurlError(CURLcode code, const char *errbuf) {
            SmtpSendResult r{};
            r.ok = false;

            auto msg = std::string(errbuf && errbuf[0] ? errbuf : curl_easy_strerror(code));
            r.error = std::move(msg);

            switch (code) {
                case CURLE_OK:
                    r.ok = true;
                    r.retryable = false;
                    r.kind = SmtpErrorKind::kNone;
                    r.error.clear();
                    return r;

                case CURLE_LOGIN_DENIED:
                case CURLE_REMOTE_ACCESS_DENIED:
                    r.kind = SmtpErrorKind::kAuth;
                    r.retryable = false;
                    return r;

                case CURLE_OPERATION_TIMEDOUT:
                    r.kind = SmtpErrorKind::kTimeout;
                    r.retryable = true;
                    return r;

                case CURLE_COULDNT_CONNECT:
                case CURLE_COULDNT_RESOLVE_HOST:
                case CURLE_COULDNT_RESOLVE_PROXY:
                case CURLE_RECV_ERROR:
                case CURLE_SEND_ERROR:
                    r.kind = SmtpErrorKind::kNetwork;
                    r.retryable = true;
                    return r;

                case CURLE_SSL_CONNECT_ERROR:
                case CURLE_PEER_FAILED_VERIFICATION:
                case CURLE_SSL_CACERT:
                case CURLE_SSL_CACERT_BADFILE:
                case CURLE_USE_SSL_FAILED:
                    r.kind = SmtpErrorKind::kTls;
                    r.retryable = (code == CURLE_SSL_CONNECT_ERROR);
                    return r;

                case CURLE_WEIRD_SERVER_REPLY:
                case CURLE_UNSUPPORTED_PROTOCOL:
                case CURLE_BAD_FUNCTION_ARGUMENT:
                    r.kind = SmtpErrorKind::kProtocol;
                    r.retryable = false;
                    return r;

                default:
                    r.kind = SmtpErrorKind::kUnknown;
                    r.retryable = true;
                    return r;
            }
        }
    }

    struct CurlSmtpClient::Impl {
        explicit Impl(SmtpConfig cfg)
            : cfg_(std::move(cfg)) {
            EnsureCurlGlobalInit();
        }

        SmtpConfig cfg_;
    };

    CurlSmtpClient::CurlSmtpClient(SmtpConfig config)
        : impl_(std::make_unique<Impl>(std::move(config))) {
    }

    CurlSmtpClient::~CurlSmtpClient() = default;

    CurlSmtpClient::CurlSmtpClient(CurlSmtpClient &&) noexcept = default;

    CurlSmtpClient &CurlSmtpClient::operator=(CurlSmtpClient &&) noexcept = default;

    SmtpSendResult CurlSmtpClient::Send(
        const std::string &mail_from,
        const std::vector<std::string> &rcpt_to,
        const Rfc822Message &message
    ) {
        if (impl_->cfg_.host.empty()) {
            return {false, false, SmtpErrorKind::kProtocol, "SMTP host is empty"};
        }
        if (impl_->cfg_.username.empty()) {
            return {false, false, SmtpErrorKind::kAuth, "SMTP username is empty"};
        }
        if (impl_->cfg_.app_password.empty()) {
            return {false, false, SmtpErrorKind::kAuth, "SMTP app_password is empty"};
        }
        if (rcpt_to.empty()) {
            return {false, false, SmtpErrorKind::kProtocol, "No recipients"};
        }
        if (message.payload.empty()) {
            return {false, false, SmtpErrorKind::kProtocol, "RFC822 payload is empty"};
        }
        if (!LooksLikeCrLfText(message.payload)) {
            return {
                false, false, SmtpErrorKind::kProtocol,
                "RFC822 payload must use CRLF (\\r\\n) line endings"
            };
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            return {false, true, SmtpErrorKind::kUnknown, "curl_easy_init failed"};
        }

        char errbuf[CURL_ERROR_SIZE];
        errbuf[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        const auto url = MakeUrl(impl_->cfg_);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        curl_easy_setopt(curl, CURLOPT_USERNAME, impl_->cfg_.username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, impl_->cfg_.app_password.c_str());

        const long use_ssl = (impl_->cfg_.tls_mode == TlsMode::kNone) ? CURLUSESSL_NONE : CURLUSESSL_ALL;
        curl_easy_setopt(curl, CURLOPT_USE_SSL, use_ssl);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                         static_cast<long>(impl_->cfg_.connect_timeout_ms.count()));
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                         static_cast<long>(impl_->cfg_.timeout_ms.count()));

        const auto envelope_from = EnsureAngleBrackets(mail_from);
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, envelope_from.c_str());

        struct curl_slist *rcpt_list = nullptr;
        std::vector<std::string> rcpt_storage;
        rcpt_storage.reserve(rcpt_to.size());

        for (const auto &r: rcpt_to) {
            rcpt_storage.push_back(EnsureAngleBrackets(r));
            rcpt_list = curl_slist_append(rcpt_list, rcpt_storage.back().c_str());
        }
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, rcpt_list);

        UploadCtx up{message.payload.data(), message.payload.size()};
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadCallback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &up);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

        const CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(rcpt_list);
        curl_easy_cleanup(curl);

        return MapCurlError(res, errbuf);
    }
}
