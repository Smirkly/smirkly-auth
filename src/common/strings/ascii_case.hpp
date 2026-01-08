#pragma once

#include <string>
#include <string_view>

namespace smirkly::auth::common::strings {
    constexpr char ToLowerAscii(char c) noexcept {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
        return c;
    }

    constexpr char ToUpperAscii(char c) noexcept {
        if (c >= 'a' && c <= 'z') return static_cast<char>(c - 'a' + 'A');
        return c;
    }

    [[nodiscard]] inline std::string ToLowerAsciiCopy(std::string_view s) {
        std::string out;
        out.resize(s.size());
        for (std::size_t i = 0; i < s.size(); ++i) out[i] = ToLowerAscii(s[i]);
        return out;
    }

    [[nodiscard]] inline std::string ToUpperAsciiCopy(std::string_view s) {
        std::string out;
        out.resize(s.size());
        for (std::size_t i = 0; i < s.size(); ++i) out[i] = ToUpperAscii(s[i]);
        return out;
    }

    inline void ToLowerAsciiInPlace(std::string &s) noexcept {
        for (char &c: s) c = ToLowerAscii(c);
    }

    inline void ToUpperAsciiInPlace(std::string &s) noexcept {
        for (char &c: s) c = ToUpperAscii(c);
    }

    [[nodiscard]] inline bool IEqualsAscii(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (ToLowerAscii(a[i]) != ToLowerAscii(b[i])) return false;
        }
        return true;
    }
}
