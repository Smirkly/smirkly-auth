#pragma once

#include <string>
#include <string_view>

namespace smirkly::auth::common::strings {
    constexpr bool IsAsciiSpace(char c) noexcept {
        return c == ' ' || c == '\t' || c == '\n' ||
               c == '\r' || c == '\f' || c == '\v';
    }

    [[nodiscard]] inline std::string_view LTrimView(std::string_view s) noexcept {
        std::size_t i = 0;
        while (i < s.size() && IsAsciiSpace(s[i])) ++i;
        return s.substr(i);
    }

    [[nodiscard]] inline std::string_view RTrimView(std::string_view s) noexcept {
        std::size_t n = s.size();
        while (n > 0 && IsAsciiSpace(s[n - 1])) --n;
        return s.substr(0, n);
    }

    [[nodiscard]] inline std::string_view TrimView(std::string_view s) noexcept {
        return RTrimView(LTrimView(s));
    }

    [[nodiscard]] inline std::string TrimCopy(std::string_view s) {
        const auto v = TrimView(s);
        return std::string{v};
    }

    inline void TrimInPlace(std::string &s) {
        const auto v = TrimView(s);
        if (v.data() == s.data() && v.size() == s.size()) return; // уже ок
        s.assign(v);
    }
}
