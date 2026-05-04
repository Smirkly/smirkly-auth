#include <auth/domain/value_objects/phone.hpp>

namespace {
    bool IsDigit(char c) noexcept {
        return c >= '0' && c <= '9';
    }

    bool IsFormattingChar(char c) noexcept {
        return c == ' ' || c == '-' || c == '(' || c == ')' || c == '\t';
    }
}

namespace smirkly::auth::domain::value_objects {
    Phone::Phone(std::string_view raw) : value_(Normalize(raw)) {
        if (value_.empty()) {
            throw std::invalid_argument("phone is empty");
        }
        if (value_.front() != '+') {
            throw std::invalid_argument("phone must use E.164 format and start with '+'");
        }

        const auto digits = value_.size() - 1;
        if (digits < kMinDigits || digits > kMaxDigits) {
            throw std::invalid_argument("phone must contain 8..15 digits");
        }

        for (std::size_t i = 1; i < value_.size(); ++i) {
            if (!IsDigit(value_[i])) {
                throw std::invalid_argument("phone must contain only digits after '+'");
            }
        }
    }

    const std::string &Phone::Value() const noexcept {
        return value_;
    }

    std::string Phone::Normalize(std::string_view raw) {
        const auto trimmed = common::strings::TrimView(raw);
        std::string value;
        value.reserve(trimmed.size());

        for (const char c: trimmed) {
            if (IsFormattingChar(c)) {
                continue;
            }
            value.push_back(c);
        }

        return value;
    }
}
