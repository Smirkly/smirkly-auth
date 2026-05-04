#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <common/strings/ascii_case.hpp>
#include <common/strings/trim.hpp>

namespace smirkly::auth::domain::value_objects {
    class Username final {
    public:
        static constexpr std::size_t kMinLength = 3;
        static constexpr std::size_t kMaxLength = 32;

        explicit Username(std::string_view raw);

        [[nodiscard]] const std::string &Value() const noexcept;

        [[nodiscard]] static std::string Normalize(std::string_view raw);

    private:
        std::string value_;
    };
}
