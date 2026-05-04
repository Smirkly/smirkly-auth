#include <auth/domain/value_objects/email.hpp>

namespace {
    bool IsAsciiControlOrSpace(char c) noexcept {
        return c <= ' ' || c == '\x7f';
    }
}

namespace smirkly::auth::domain::value_objects {
    Email::Email(std::string_view raw) : value_(Normalize(raw)) {
        if (value_.empty()) {
            throw std::invalid_argument("email is empty");
        }
        if (value_.size() > kMaxLength) {
            throw std::invalid_argument("email is too long");
        }

        const auto at = value_.find('@');
        if (at == std::string::npos || at == 0 || at + 1 == value_.size()) {
            throw std::invalid_argument("email must contain local and domain parts");
        }
        if (value_.find('@', at + 1) != std::string::npos) {
            throw std::invalid_argument("email must contain a single '@'");
        }

        const auto domain = std::string_view{value_}.substr(at + 1);
        if (domain.find('.') == std::string_view::npos ||
            domain.front() == '.' ||
            domain.back() == '.') {
            throw std::invalid_argument("email domain is invalid");
        }

        for (const char c: value_) {
            if (IsAsciiControlOrSpace(c)) {
                throw std::invalid_argument("email must not contain spaces or control characters");
            }
        }
    }

    const std::string &Email::Value() const noexcept {
        return value_;
    }

    std::string Email::Normalize(std::string_view raw) {
        auto value = common::strings::TrimCopy(raw);
        common::strings::ToLowerAsciiInPlace(value);
        return value;
    }
}
