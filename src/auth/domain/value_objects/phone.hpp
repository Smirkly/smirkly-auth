#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <common/strings/ascii_case.hpp>
#include <common/strings/trim.hpp>

namespace smirkly::auth::domain::value_objects {
    class Phone final {
    public:
        static constexpr std::size_t kMinDigits = 8;
        static constexpr std::size_t kMaxDigits = 15;

        explicit Phone(std::string_view raw);

        [[nodiscard]] const std::string &Value() const noexcept;

        [[nodiscard]] static std::string Normalize(std::string_view raw);

    private:
        std::string value_;
    };
}
