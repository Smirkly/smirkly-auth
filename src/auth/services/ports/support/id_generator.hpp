#pragma once

#include <string>

namespace smirkly::auth::services::ports::support {
    class IdGenerator {
    public:
        virtual ~IdGenerator() = default;

        [[nodiscard]] virtual std::string Generate() = 0;
    };
}
