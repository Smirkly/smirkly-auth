#include <auth/domain/value_objects/username.hpp>

namespace {
    bool IsAllowedUsernameChar(char c) noexcept {
        return (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '_';
    }
}

namespace smirkly::auth::domain::value_objects {
    Username::Username(std::string_view raw) : value_(Normalize(raw)) {
        if (value_.size() < kMinLength || value_.size() > kMaxLength) {
            throw std::invalid_argument("username must be 3..32 characters long");
        }

        for (const char c: value_) {
            if (!IsAllowedUsernameChar(c)) {
                throw std::invalid_argument("username may contain only lowercase latin letters, digits and underscore");
            }
        }

        if (value_.front() == '_' || value_.back() == '_') {
            throw std::invalid_argument("username must not start or end with underscore");
        }
    }

    const std::string &Username::Value() const noexcept {
        return value_;
    }

    std::string Username::Normalize(std::string_view raw) {
        auto value = common::strings::TrimCopy(raw);
        common::strings::ToLowerAsciiInPlace(value);
        return value;
    }
}
