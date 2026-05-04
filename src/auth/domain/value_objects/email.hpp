#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <common/strings/ascii_case.hpp>
#include <common/strings/trim.hpp>

namespace smirkly::auth::domain::value_objects {
    class Email final {
    public:
        static constexpr std::size_t kMaxLength = 254;

        explicit Email(std::string_view raw);

        [[nodiscard]] const std::string &Value() const noexcept;

        [[nodiscard]] static std::string Normalize(std::string_view raw);

    private:
        std::string value_;
    };
}
